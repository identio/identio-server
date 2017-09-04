package net.identio.server.model;

import java.util.List;

public class DataSourcesConfiguration {

    private List<DataSource> dataSources;

    public List<DataSource> getDataSources() {
        return dataSources;
    }

    public void setDataSources(List<DataSource> dataSources) {
        this.dataSources = dataSources;
    }
}
