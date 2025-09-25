package org.wso2.carbon.utils.internal;

import org.apache.axis2.context.ConfigurationContext;
import org.wso2.carbon.base.api.ServerConfigurationService;
import org.wso2.carbon.utils.CarbonUtils;

public class CarbonUtilsDataHolder {
    private static ConfigurationContext configContext;
    private static ServerConfigurationService serverConfigurationService;

    public static void setConfigContext(ConfigurationContext configContext) {
        CarbonUtilsDataHolder.configContext = configContext;
    }

    public static ConfigurationContext getConfigContext() {
        CarbonUtils.checkSecurity();
        return configContext;
    }

}
