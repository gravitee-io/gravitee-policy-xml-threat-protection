package com.graviteesource.policy.threatprotection.xml.deployer;

import io.gravitee.node.api.deployer.AbstractPluginDeploymentLifecycle;

/**
 * @author Kamiel Ahmadpour (kamiel.ahmadpour at graviteesource.com)
 * @author GraviteeSource Team
 */
public class XmlThreatProtectionPolicyDeploymentLifecycle extends AbstractPluginDeploymentLifecycle {

    private static final String XML_THREAT_PROTECTION_POLICY = "apim-policy-xml-threat-protection";

    @Override
    protected String getFeatureName() {
        return XML_THREAT_PROTECTION_POLICY;
    }
}
