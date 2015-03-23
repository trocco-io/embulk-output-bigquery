package org.embulk.output;

import java.io.File;
import java.io.IOException;
import java.io.FileNotFoundException;
import java.io.FileInputStream;
import com.google.api.client.http.FileContent;
import com.google.api.client.http.InputStreamContent;
import java.util.ArrayList;
import java.util.List;
import java.util.Iterator;
import java.util.HashMap;
import java.util.IllegalFormatException;
import java.util.concurrent.Callable;
import java.util.concurrent.TimeoutException;
import org.apache.commons.lang3.StringUtils;
import com.google.common.base.Optional;
import com.google.common.collect.ImmutableSet;
import java.security.GeneralSecurityException;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.core.type.TypeReference;

import org.embulk.spi.Exec;
import org.slf4j.Logger;

import com.google.api.services.bigquery.Bigquery;
import com.google.api.services.bigquery.BigqueryScopes;
import com.google.api.services.bigquery.Bigquery.Datasets;
import com.google.api.services.bigquery.Bigquery.Tables;
import com.google.api.services.bigquery.Bigquery.Jobs.Insert;
import com.google.api.services.bigquery.Bigquery.Jobs.GetQueryResults;
import com.google.api.services.bigquery.model.Job;
import com.google.api.services.bigquery.model.JobConfiguration;
import com.google.api.services.bigquery.model.JobConfigurationLoad;
import com.google.api.services.bigquery.model.JobStatus;
import com.google.api.services.bigquery.model.JobStatistics;
import com.google.api.services.bigquery.model.JobReference;
import com.google.api.services.bigquery.model.DatasetList;
import com.google.api.services.bigquery.model.Table;
import com.google.api.services.bigquery.model.TableList;
import com.google.api.services.bigquery.model.TableSchema;
import com.google.api.services.bigquery.model.TableReference;
import com.google.api.services.bigquery.model.TableFieldSchema;
import com.google.api.services.bigquery.model.TableCell;
import com.google.api.services.bigquery.model.TableRow;
import com.google.api.services.bigquery.model.ErrorProto;
import com.google.api.client.googleapis.json.GoogleJsonResponseException;

public class BigqueryWriter
{

    private final Logger log = Exec.getLogger(BigqueryWriter.class);
    private final String project;
    private final String dataset;
    private final String table;
    private final boolean autoCreateTable;
    private final Optional<String> schemaPath;
    private final String sourceFormat;
    private final String fieldDelimiter;
    private final int maxBadrecords;
    private final long jobStatusMaxPollingTime;
    private final long jobStatusPollingInterval;
    private final boolean isSkipJobResultCheck;
    private final Bigquery bigQueryClient;

    public BigqueryWriter(Builder builder) throws IOException, GeneralSecurityException
    {
        this.project = builder.project;
        this.dataset = builder.dataset;
        this.table = builder.table;
        this.autoCreateTable = builder.autoCreateTable;
        this.schemaPath = builder.schemaPath;
        this.sourceFormat = builder.sourceFormat.toUpperCase();
        this.fieldDelimiter = builder.fieldDelimiter;
        this.maxBadrecords = builder.maxBadrecords;
        this.jobStatusMaxPollingTime = builder.jobStatusMaxPollingTime;
        this.jobStatusPollingInterval = builder.jobStatusPollingInterval;
        this.isSkipJobResultCheck = builder.isSkipJobResultCheck;

        BigqueryAuthentication auth = new BigqueryAuthentication(builder.serviceAccountEmail, builder.p12KeyFilePath, builder.applicationName);
        this.bigQueryClient = auth.getBigqueryClient();
    }

    private String getJobStatus(JobReference jobRef) throws JobFailedException
    {
        try {
            Job job = bigQueryClient.jobs().get(project, jobRef.getJobId()).execute();

            ErrorProto fatalError = job.getStatus().getErrorResult();
            if (fatalError != null) {
                throw new JobFailedException(String.format("Job failed. job id:[%s] reason:[%s][%s] status:[FAILED]", jobRef.getJobId(), fatalError.getReason(), fatalError.getMessage()));
            }
            List<ErrorProto> errors = job.getStatus().getErrors();
            if (errors != null) {
                for (ErrorProto error : errors) {
                    log.warn(String.format("Error: job id:[%s] reason[%s][%s] location:[%s]", jobRef.getJobId(), error.getReason(), error.getMessage(), error.getLocation()));
                }
            }

            String jobStatus = job.getStatus().getState();
            if (jobStatus.equals("DONE")) {
                JobStatistics statistics = job.getStatistics();
                //log.info(String.format("Job end. create:[%s] end:[%s]", statistics.getCreationTime(), statistics.getEndTime()));
                log.info(String.format("Job statistics [%s]", statistics.getLoad()));
            }
            return jobStatus;
        } catch (IOException ex) {
            log.warn(ex.getMessage());
            return "UNKNOWN";
        }
    }

    private void getJobStatusUntilDone(JobReference jobRef) throws TimeoutException, JobFailedException
    {
        long startTime = System.currentTimeMillis();
        long elapsedTime;

        try {
            while (true) {
                String jobStatus = getJobStatus(jobRef);
                elapsedTime = System.currentTimeMillis() - startTime;
                if (jobStatus.equals("DONE")) {
                    log.info(String.format("Job completed successfully. job id:[%s] elapsed_time:%dms status:[%s]", jobRef.getJobId(), elapsedTime, "SUCCESS"));
                    break;
                } else if (elapsedTime > jobStatusMaxPollingTime * 1000) {
                    throw new TimeoutException(String.format("Checking job status...Timeout. job id:[%s] elapsed_time:%dms status:[%s]", jobRef.getJobId(), elapsedTime, "TIMEOUT"));
                } else {
                    log.info(String.format("Checking job status... job id:[%s] elapsed_time:%dms status:[%s]", jobRef.getJobId(), elapsedTime, jobStatus));
                }
                Thread.sleep(jobStatusPollingInterval * 1000);
            }
        } catch (InterruptedException ex) {
            log.warn(ex.getMessage());
        }
    }

    public void executeLoad(String localFilePath) throws IOException, TimeoutException, JobFailedException
    {
        log.info(String.format("Job preparing... project:%s dataset:%s table:%s", project, dataset, table));

        Job job = new Job();
        JobConfiguration jobConfig = new JobConfiguration();
        JobConfigurationLoad loadConfig = new JobConfigurationLoad();
        jobConfig.setLoad(loadConfig);
        job.setConfiguration(jobConfig);

        loadConfig.setAllowQuotedNewlines(false);
        if (sourceFormat.equals("NEWLINE_DELIMITED_JSON")) {
            loadConfig.setSourceFormat("NEWLINE_DELIMITED_JSON");
        } else {
            loadConfig.setFieldDelimiter(fieldDelimiter);
        }
        loadConfig.setWriteDisposition("WRITE_APPEND");
        if (autoCreateTable) {
            loadConfig.setSchema(getTableSchema());
            loadConfig.setCreateDisposition("CREATE_IF_NEEDED");
            log.info(String.format("table:[%s] will be create if not exists", table));
        } else {
            loadConfig.setCreateDisposition("CREATE_NEVER");
        }
        loadConfig.setMaxBadRecords(maxBadrecords);

        loadConfig.setDestinationTable(getTableReference());

        log.info(String.format("Uploading file [%s]", localFilePath));
        File file = new File(localFilePath);
        FileContent mediaContent = new FileContent("application/octet-stream", file);

        Insert insert = bigQueryClient.jobs().insert(project, job, mediaContent);
        insert.setDisableGZipContent(true);
        insert.setProjectId(project);
        JobReference jobRef = insert.execute().getJobReference();
        log.info(String.format("Job executed. job id:[%s]", jobRef.getJobId()));
        if (isSkipJobResultCheck) {
            log.info(String.format("Skip job status check. job id:[%s]", jobRef.getJobId()));
        } else {
            getJobStatusUntilDone(jobRef);
        }
    }

    private TableReference getTableReference()
    {
        return new TableReference()
                .setProjectId(project)
                .setDatasetId(dataset)
                .setTableId(table);
    }

    private TableSchema getTableSchema() throws FileNotFoundException, IOException
    {
        String path = schemaPath.orNull();
        File file = new File(path);
        FileInputStream stream = null;
        try {
            stream = new FileInputStream(file);
            ObjectMapper mapper = new ObjectMapper();
            List<TableFieldSchema> fields = mapper.readValue(stream, new TypeReference<List<TableFieldSchema>>() {});
            TableSchema tableSchema = new TableSchema().setFields(fields);
            return tableSchema;
        } finally {
            if (stream != null) {
                stream.close();
            }
        }
    }

    public boolean isExistTable(String tableName) throws IOException{
        Tables tableRequest = bigQueryClient.tables();
        try {
            Table tableData = tableRequest.get(project, dataset, tableName).execute();
        } catch (GoogleJsonResponseException ex) {
            return false;
        }
        return true;
    }

    public void checkConfig() throws FileNotFoundException, IOException
    {
        if (autoCreateTable) {
            if (schemaPath != null) {
                File file = new File(schemaPath.orNull());
                if (!file.exists()) {
                    throw new FileNotFoundException("Can not load schema file.");
                }
            }
        } else {
            if(!isExistTable(table)) {
                throw new IOException(String.format("table [%s] is not exists", table));
            }
        }
    }

    public static class Builder
    {
        private final String serviceAccountEmail;
        private String p12KeyFilePath;
        private String applicationName;
        private String project;
        private String dataset;
        private String table;
        private boolean autoCreateTable;
        private Optional<String> schemaPath;
        private String sourceFormat;
        private String fieldDelimiter;
        private int maxBadrecords;
        private int jobStatusMaxPollingTime;
        private int jobStatusPollingInterval;
        private boolean isSkipJobResultCheck;


        public Builder(String serviceAccountEmail)
        {
            this.serviceAccountEmail = serviceAccountEmail;
        }

        public Builder setP12KeyFilePath(String p12KeyFilePath)
        {
            this.p12KeyFilePath = p12KeyFilePath;
            return this;
        }

        public Builder setApplicationName(String applicationName)
        {
            this.applicationName = applicationName;
            return this;
        }

        public Builder setProject(String project)
        {
            this.project = project;
            return this;
        }

        public Builder setDataset(String dataset)
        {
            this.dataset = dataset;
            return this;
        }

        public Builder setTable(String table)
        {
            this.table = table;
            return this;
        }

        public Builder setAutoCreateTable(boolean autoCreateTable)
        {
            this.autoCreateTable = autoCreateTable;
            return this;
        }

        public Builder setSchemaPath(Optional<String> schemaPath)
        {
            this.schemaPath = schemaPath;
            return this;
        }

        public Builder setSourceFormat(String sourceFormat)
        {
            this.sourceFormat = sourceFormat;
            return this;
        }

        public Builder setFieldDelimiter(String fieldDelimiter)
        {
            this.fieldDelimiter = fieldDelimiter;
            return this;
        }

        public Builder setMaxBadrecords(int maxBadrecords)
        {
            this.maxBadrecords = maxBadrecords;
            return this;
        }

        public Builder setJobStatusMaxPollingTime(int jobStatusMaxPollingTime)
        {
            this.jobStatusMaxPollingTime = jobStatusMaxPollingTime;
            return this;
        }

        public Builder setJobStatusPollingInterval(int jobStatusPollingInterval)
        {
            this.jobStatusPollingInterval = jobStatusPollingInterval;
            return this;
        }

        public Builder setIsSkipJobResultCheck(boolean isSkipJobResultCheck)
        {
            this.isSkipJobResultCheck = isSkipJobResultCheck;
            return this;
        }

        public BigqueryWriter build() throws IOException, GeneralSecurityException
        {
            return new BigqueryWriter(this);
        }
    }

    public class JobFailedException extends Exception
    {
        public JobFailedException(String message) {
            super(message);
        }
    }
}