/**
 * Copyright (C) 2015 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.gravitee.policy.threatprotection.xml;

import com.ctc.wstx.api.WstxInputProperties;
import com.ctc.wstx.stax.WstxInputFactory;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import io.gravitee.common.http.HttpStatusCode;
import io.gravitee.common.http.MediaType;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.buffer.Buffer;
import io.gravitee.gateway.api.http.HttpHeaderNames;
import io.gravitee.gateway.api.http.stream.TransformableRequestStreamBuilder;
import io.gravitee.gateway.api.stream.ReadWriteStream;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyConfiguration;
import io.gravitee.policy.api.PolicyResult;
import io.gravitee.policy.api.annotations.OnRequestContent;

import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import java.io.StringReader;
import java.time.Duration;
import java.util.Collections;
import java.util.concurrent.ExecutionException;
import java.util.regex.Pattern;

import static io.gravitee.common.http.MediaType.MEDIA_TEXT_XML;

/**
 * @author Jeoffrey HAEYAERT (jeoffrey.haeyaert at graviteesource.com)
 * @author GraviteeSource Team
 */
public class XmlThreatProtectionPolicy {

    private static final String SERVER_ERROR = "Server error";
    private final static String BAD_REQUEST = "Bad Request";
    private static final String XML_THREAT_DETECTED_KEY = "XML_THREAT_DETECTED";
    private static final String XML_THREAT_MAX_ATTRIBUTES_KEY = "XML_THREAT_MAX_ATTRIBUTES";
    private static final String XML_THREAT_MAX_ATTRIBUTE_VALUE_LENGTH_KEY = "XML_THREAT_MAX_ATTRIBUTE_VALUE_LENGTH";
    private static final String XML_THREAT_MAX_ELEMENTS_KEY = "XML_THREAT_MAX_ELEMENTS";
    private static final String XML_THREAT_MAX_ENTITIES_KEY = "XML_THREAT_MAX_ENTITIES";
    private static final String XML_THREAT_MAX_DEPTH_KEY = "XML_THREAT_MAX_DEPTH";
    private static final String XML_THREAT_MAX_ENTITY_DEPTH_KEY = "XML_THREAT_MAX_ENTITY_DEPTH";
    private static final String XML_THREAT_MAX_CHILD_ELEMENTS_KEY = "XML_THREAT_MAX_CHILD_ELEMENTS";
    private static final String XML_THREAT_MAX_LENGTH_KEY = "XML_THREAT_MAX_LENGTH";
    private static final String XML_THREAT_MAX_TEXT_VALUE_LENGTH_KEY = "XML_THREAT_MAX_TEXT_VALUE_LENGTH";
    private static final String XML_THREAT_EXTERNAL_ENTITY_FORBIDDEN_KEY = "XML_THREAT_EXTERNAL_ENTITY_FORBIDDEN";

    /**
     * XML parser does not provide a simple way to identify error type.
     * Using patterns to map parser exception to error key and allow message customization.
     */
    private static final Pattern EXCEPTION_PATTERN_MAX_ATTRIBUTES = Pattern.compile(".*Attribute limit \\(\\d+\\) exceeded.*", Pattern.CASE_INSENSITIVE);
    private static final Pattern EXCEPTION_PATTERN_MAX_ATTRIBUTE_VALUE_LENGTH = Pattern.compile(".*Maximum attribute size limit \\(\\d+\\) exceeded.*", Pattern.CASE_INSENSITIVE);
    private static final Pattern EXCEPTION_PATTERN_MAX_ELEMENTS = Pattern.compile(".*Maximum Element Count limit \\(\\d+\\) Exceeded.*", Pattern.CASE_INSENSITIVE);
    private static final Pattern EXCEPTION_PATTERN_MAX_ENTITIES = Pattern.compile(".*Maximum entity expansion count limit \\(\\d+\\) exceeded.*", Pattern.CASE_INSENSITIVE);
    private static final Pattern EXCEPTION_PATTERN_MAX_DEPTH = Pattern.compile(".*Maximum Element Depth limit \\(\\d*\\) Exceeded.*", Pattern.CASE_INSENSITIVE);
    private static final Pattern EXCEPTION_PATTERN_MAX_ENTITY_DEPTH = Pattern.compile(".*Maximum entity expansion depth limit \\(\\d+\\) exceeded.*", Pattern.CASE_INSENSITIVE);
    private static final Pattern EXCEPTION_PATTERN_MAX_CHILD_ELEMENTS = Pattern.compile(".*Maximum Number of Child Elements limit \\(\\d+\\) Exceeded.*", Pattern.CASE_INSENSITIVE);
    private static final Pattern EXCEPTION_PATTERN_MAX_LENGTH = Pattern.compile(".*Maximum document characters limit \\(\\d+\\) exceeded.*", Pattern.CASE_INSENSITIVE);
    private static final Pattern EXCEPTION_PATTERN_MAX_TEXT_VALUE_LENGTH = Pattern.compile(".*Text size limit \\(\\d+\\) exceeded.*", Pattern.CASE_INSENSITIVE);
    private static final Pattern EXCEPTION_PATTERN_EXTERNAL_ENTITY_FORBIDDEN = Pattern.compile(".*Encountered a reference to external entity .* but stream reader has feature \"javax\\.xml\\.stream\\.isSupportingExternalEntities\" disabled.*", Pattern.CASE_INSENSITIVE | Pattern.DOTALL);

    /**
     * Number of hours to keep XMLFactories in cache after the last time it was accessed.
     */
    private static final int CACHE_EXPIRATION_HOURS = 1;

    /**
     * Max number of entries in the cache.
     */
    private static final int CACHE_MAXIMUM_SIZE = 1000;

    private static final Cache<PolicyConfiguration, XMLInputFactory> factories = CacheBuilder.newBuilder()
            .maximumSize(CACHE_MAXIMUM_SIZE)
            .expireAfterAccess(Duration.ofHours(CACHE_EXPIRATION_HOURS)).build();

    private final XmlThreatProtectionPolicyConfiguration configuration;

    public XmlThreatProtectionPolicy(XmlThreatProtectionPolicyConfiguration configuration) {
        this.configuration = configuration;
    }

    private XMLInputFactory getXmlFactory() throws RuntimeException {

        // Factory will be kept in cache until expiration or eviction occurs.
        try {
            return factories.get(configuration, () -> {
                 XMLInputFactory xmlFactory = new WstxInputFactory();
                 xmlFactory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, configuration.isAllowExternalEntities());
                 setXmlFactoryProperty(xmlFactory, WstxInputProperties.P_MAX_ATTRIBUTE_SIZE, configuration.getMaxAttributeValueLength());
                 setXmlFactoryProperty(xmlFactory, WstxInputProperties.P_MAX_TEXT_LENGTH, configuration.getMaxTextValueLength());
                 setXmlFactoryProperty(xmlFactory, WstxInputProperties.P_MAX_ATTRIBUTES_PER_ELEMENT, configuration.getMaxAttributesPerElement());
                 setXmlFactoryProperty(xmlFactory, WstxInputProperties.P_MAX_CHILDREN_PER_ELEMENT, configuration.getMaxChildrenPerElement());
                 setXmlFactoryProperty(xmlFactory, WstxInputProperties.P_MAX_ELEMENT_COUNT, configuration.getMaxElements());
                 setXmlFactoryProperty(xmlFactory, WstxInputProperties.P_MAX_ELEMENT_DEPTH, configuration.getMaxDepth());
                 setXmlFactoryProperty(xmlFactory, WstxInputProperties.P_MAX_ENTITY_COUNT, configuration.getMaxEntities());
                 setXmlFactoryProperty(xmlFactory, WstxInputProperties.P_MAX_ENTITY_DEPTH, configuration.getMaxEntityDepth());
                 setXmlFactoryProperty(xmlFactory, WstxInputProperties.P_MAX_CHARACTERS, configuration.getMaxLength());

                 return xmlFactory;
             });
        } catch (ExecutionException e) {
            throw new RuntimeException(e);
        }
    }

    @OnRequestContent
    public ReadWriteStream<Buffer> onRequestContent(Request request, PolicyChain policyChain) {

        if (request.headers().getOrDefault(HttpHeaderNames.CONTENT_TYPE, Collections.emptyList()).stream().anyMatch(ct -> ct.endsWith(MEDIA_TEXT_XML.getSubtype()))) {
            // The policy is only applicable to json content type.
            return TransformableRequestStreamBuilder
                    .on(request)
                    .chain(policyChain)
                    .transform(buffer -> {
                        try {
                            validateXml(buffer.toString());
                        } catch (XmlException e) {
                            policyChain.streamFailWith(PolicyResult.failure(e.getKey(), HttpStatusCode.BAD_REQUEST_400, BAD_REQUEST, MediaType.TEXT_PLAIN));
                        } catch (Exception e) {
                            policyChain.streamFailWith(PolicyResult.failure(HttpStatusCode.INTERNAL_SERVER_ERROR_500, SERVER_ERROR, MediaType.TEXT_PLAIN));
                        }

                        return buffer;
                    }).build();
        }

        return null;
    }

    private void validateXml(String xml) throws XmlException {

        XMLEventReader xmlEventReader = null;

        try {
            xmlEventReader = getXmlFactory().createXMLEventReader(new StringReader(xml));
            while (xmlEventReader.hasNext()) {
                // Just consume events and wait for an exception in case of violation.
                xmlEventReader.nextEvent();
            }
        } catch (XMLStreamException e) {
            throw convert(e);
        } finally {
            if (xmlEventReader != null) {
                try {
                    xmlEventReader.close();
                } catch (Exception ignored) {
                }
            }
        }
    }

    /**
     * Set factory property checking for <code>null</code> or negative value to be replaced with {@link Integer#MAX_VALUE}.
     *
     * @param property the property name.
     * @param value the corresponding property value.
     */
    private void setXmlFactoryProperty(XMLInputFactory xmlFactory, String property, Integer value) {

        if (value != null && value >= 0) {
            xmlFactory.setProperty(property, value);
        } else {
            xmlFactory.setProperty(property, Integer.MAX_VALUE);
        }
    }

    private static XmlException convert(XMLStreamException xmlStreamException) {

        if (EXCEPTION_PATTERN_MAX_LENGTH.matcher(xmlStreamException.getMessage()).matches()) {
            return new XmlException(XML_THREAT_MAX_LENGTH_KEY, xmlStreamException.getMessage());
        }

        if (EXCEPTION_PATTERN_MAX_TEXT_VALUE_LENGTH.matcher(xmlStreamException.getMessage()).matches()) {
            return new XmlException(XML_THREAT_MAX_TEXT_VALUE_LENGTH_KEY, xmlStreamException.getMessage());
        }

        if (EXCEPTION_PATTERN_MAX_ATTRIBUTES.matcher(xmlStreamException.getMessage()).matches()) {
            return new XmlException(XML_THREAT_MAX_ATTRIBUTES_KEY, xmlStreamException.getMessage());
        }

        if (EXCEPTION_PATTERN_MAX_ATTRIBUTE_VALUE_LENGTH.matcher(xmlStreamException.getMessage()).matches()) {
            return new XmlException(XML_THREAT_MAX_ATTRIBUTE_VALUE_LENGTH_KEY, xmlStreamException.getMessage());
        }

        if (EXCEPTION_PATTERN_MAX_ELEMENTS.matcher(xmlStreamException.getMessage()).matches()) {
            return new XmlException(XML_THREAT_MAX_ELEMENTS_KEY, xmlStreamException.getMessage());
        }

        if (EXCEPTION_PATTERN_MAX_ENTITIES.matcher(xmlStreamException.getMessage()).matches()) {
            return new XmlException(XML_THREAT_MAX_ENTITIES_KEY, xmlStreamException.getMessage());
        }

        if (EXCEPTION_PATTERN_MAX_DEPTH.matcher(xmlStreamException.getMessage()).matches()) {
            return new XmlException(XML_THREAT_MAX_DEPTH_KEY, xmlStreamException.getMessage());
        }

        if (EXCEPTION_PATTERN_MAX_ENTITY_DEPTH.matcher(xmlStreamException.getMessage()).matches()) {
            return new XmlException(XML_THREAT_MAX_ENTITY_DEPTH_KEY, xmlStreamException.getMessage());
        }

        if (EXCEPTION_PATTERN_MAX_CHILD_ELEMENTS.matcher(xmlStreamException.getMessage()).matches()) {
            return new XmlException(XML_THREAT_MAX_CHILD_ELEMENTS_KEY, xmlStreamException.getMessage());
        }

        if (EXCEPTION_PATTERN_EXTERNAL_ENTITY_FORBIDDEN.matcher(xmlStreamException.getMessage()).matches()) {
            return new XmlException(XML_THREAT_EXTERNAL_ENTITY_FORBIDDEN_KEY, xmlStreamException.getMessage());
        }

        return new XmlException(XML_THREAT_DETECTED_KEY, xmlStreamException.getMessage());
    }
}
