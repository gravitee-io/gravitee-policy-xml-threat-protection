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

import io.gravitee.policy.api.PolicyConfiguration;

/**
 * @author Jeoffrey HAEYAERT (jeoffrey.haeyaert at graviteesource.com)
 * @author GraviteeSource Team
 */
public class XmlThreatProtectionPolicyConfiguration implements PolicyConfiguration {

    /**
     * Maximum number of all elements in a whole document.
     */
    private Integer maxElements;

    /**
     * Maximum depth of XML elements, starting with root element.
     */
    private Integer maxDepth;

    /**
     * Maximum number of characters allowed for the whole xml document.
     */
    private Integer maxLength;

    /**
     * Maximum number of attributes allowed for single XML element.
     */
    private Integer maxAttributesPerElement;

    /**
     * Maximum length of individual attribute values.
     */
    private Integer maxAttributeValueLength;

    /**
     * Maximum number of child elements for a given element.
     */
    private Integer maxChildrenPerElement;

    /**
     * Maximum length of individual text.
     */
    private Integer maxTextValueLength;

    /**
     * Maximum number of entity expansions allowed.
     */
    private Integer maxEntities;

    /**
     * Maximum depth of nested entity expansions.
     */
    private Integer maxEntityDepth;

    /**
     * Whether to allow external entities or not.
     * Default is false.
     */
    private boolean allowExternalEntities = false;

    public Integer getMaxAttributesPerElement() {
        return maxAttributesPerElement;
    }

    public void setMaxAttributesPerElement(Integer maxAttributesPerElement) {
        this.maxAttributesPerElement = maxAttributesPerElement;
    }

    public Integer getMaxAttributeValueLength() {
        return maxAttributeValueLength;
    }

    public void setMaxAttributeValueLength(Integer maxAttributeValueLength) {
        this.maxAttributeValueLength = maxAttributeValueLength;
    }

    public Integer getMaxChildrenPerElement() {
        return maxChildrenPerElement;
    }

    public void setMaxChildrenPerElement(Integer maxChildrenPerElement) {
        this.maxChildrenPerElement = maxChildrenPerElement;
    }

    public Integer getMaxElements() {
        return maxElements;
    }

    public void setMaxElements(Integer maxElements) {
        this.maxElements = maxElements;
    }

    public Integer getMaxDepth() {
        return maxDepth;
    }

    public void setMaxDepth(Integer maxDepth) {
        this.maxDepth = maxDepth;
    }

    public Integer getMaxTextValueLength() {
        return maxTextValueLength;
    }

    public void setMaxTextValueLength(Integer maxTextValueLength) {
        this.maxTextValueLength = maxTextValueLength;
    }

    public Integer getMaxEntities() {
        return maxEntities;
    }

    public void setMaxEntities(Integer maxEntities) {
        this.maxEntities = maxEntities;
    }

    public Integer getMaxEntityDepth() {
        return maxEntityDepth;
    }

    public void setMaxEntityDepth(Integer maxEntityDepth) {
        this.maxEntityDepth = maxEntityDepth;
    }

    public Integer getMaxLength() {
        return maxLength;
    }

    public void setMaxLength(Integer maxLength) {
        this.maxLength = maxLength;
    }

    public boolean isAllowExternalEntities() {
        return allowExternalEntities;
    }

    public void setAllowExternalEntities(boolean allowExternalEntities) {
        this.allowExternalEntities = allowExternalEntities;
    }
}
