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

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import io.gravitee.common.http.MediaType;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.buffer.Buffer;
import io.gravitee.gateway.api.http.HttpHeaderNames;
import io.gravitee.gateway.api.http.HttpHeaders;
import io.gravitee.gateway.api.stream.BufferedReadWriteStream;
import io.gravitee.gateway.api.stream.ReadWriteStream;
import io.gravitee.gateway.api.stream.SimpleReadWriteStream;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyResult;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;

/**
 * @author Jeoffrey HAEYAERT (jeoffrey.haeyaert at graviteesource.com)
 * @author GraviteeSource Team
 */
@RunWith(MockitoJUnitRunner.class)
public class XmlThreatProtectionPolicyTest {

    @Mock
    private Request request;

    @Mock
    private PolicyChain policyChain;

    XmlThreatProtectionPolicyConfiguration configuration;

    private XmlThreatProtectionPolicy cut;

    @Rule
    public WireMockRule wireMockRule = new WireMockRule(wireMockConfig().dynamicPort());

    @Before
    public void before() {
        configuration = new XmlThreatProtectionPolicyConfiguration();
        configuration.setMaxChildrenPerElement(100);
        configuration.setMaxDepth(1000);
        configuration.setMaxAttributesPerElement(100);
        configuration.setMaxAttributeValueLength(100);
        configuration.setMaxElements(100);
        configuration.setMaxEntities(100);
        configuration.setMaxEntityDepth(1000);
        configuration.setMaxTextValueLength(100);
        configuration.setMaxLength(1000);

        HttpHeaders httpHeaders = HttpHeaders.create().add(HttpHeaderNames.CONTENT_TYPE, MediaType.APPLICATION_XML);
        when(request.headers()).thenReturn(httpHeaders);
    }

    @Test
    public void shouldAcceptAllWhenContentTypeIsNotXml() {
        Mockito.reset(request);
        cut = new XmlThreatProtectionPolicy(configuration);
        when(request.headers()).thenReturn(HttpHeaders.create());
        ReadWriteStream<?> readWriteStream = cut.onRequestContent(request, policyChain);

        assertThat(readWriteStream).isNull();
    }

    @Test
    public void shouldAcceptValidXml() {
        cut = new XmlThreatProtectionPolicy(configuration);
        ReadWriteStream<Buffer> readWriteStream = cut.onRequestContent(request, policyChain);

        assertThat(readWriteStream).isNotNull();

        final AtomicBoolean hasCalledEndOnReadWriteStreamParentClass = spyEndHandler(readWriteStream);

        readWriteStream.write(Buffer.buffer("<test valid=\"true\">value</test>"));
        readWriteStream.end();

        assertThat(hasCalledEndOnReadWriteStreamParentClass).isTrue();

        verifyNoInteractions(policyChain);
    }

    @Test
    public void shouldRejectInvalidXml() {
        cut = new XmlThreatProtectionPolicy(configuration);
        ReadWriteStream<Buffer> readWriteStream = cut.onRequestContent(request, policyChain);

        assertThat(readWriteStream).isNotNull();

        final AtomicBoolean hasCalledEndOnReadWriteStreamParentClass = spyEndHandler(readWriteStream);

        readWriteStream.write(Buffer.buffer("Invalid"));
        readWriteStream.end();

        assertThat(hasCalledEndOnReadWriteStreamParentClass).isFalse();

        verify(policyChain, times(1)).streamFailWith(any(PolicyResult.class));
    }

    @Test
    public void shouldRejectWhenMaxTextValueLengthExceeded() {
        configuration.setMaxTextValueLength(4);
        cut = new XmlThreatProtectionPolicy(configuration);
        ReadWriteStream<Buffer> readWriteStream = cut.onRequestContent(request, policyChain);

        assertThat(readWriteStream).isNotNull();

        final AtomicBoolean hasCalledEndOnReadWriteStreamParentClass = spyEndHandler(readWriteStream);

        readWriteStream.write(Buffer.buffer("<test valid=\"true\">value</test>"));
        readWriteStream.end();

        assertThat(hasCalledEndOnReadWriteStreamParentClass).isFalse();

        verify(policyChain, times(1)).streamFailWith(any(PolicyResult.class));
    }

    @Test
    public void shouldRejectWhenMaxLengthExceeded() {
        configuration.setMaxLength(1);
        cut = new XmlThreatProtectionPolicy(configuration);
        ReadWriteStream<Buffer> readWriteStream = cut.onRequestContent(request, policyChain);

        assertThat(readWriteStream).isNotNull();
        final AtomicBoolean hasCalledEndOnReadWriteStreamParentClass = spyEndHandler(readWriteStream);

        readWriteStream.write(Buffer.buffer("<test valid=\"false\">1234</test>"));
        readWriteStream.end();

        assertThat(hasCalledEndOnReadWriteStreamParentClass).isFalse();

        verify(policyChain, times(1)).streamFailWith(any(PolicyResult.class));
    }

    @Test
    public void shouldRejectWhenMaxAttributesPerElementExceeded() {
        configuration.setMaxAttributesPerElement(1);
        cut = new XmlThreatProtectionPolicy(configuration);
        ReadWriteStream<Buffer> readWriteStream = cut.onRequestContent(request, policyChain);

        assertThat(readWriteStream).isNotNull();
        final AtomicBoolean hasCalledEndOnReadWriteStreamParentClass = spyEndHandler(readWriteStream);

        readWriteStream.write(
            Buffer.buffer(
                "<test valid=\"true\" valid2=\"false\" valid3=\"false\" valid4=\"false\" valid5=\"false\" valid6=\"false\" valid7=\"false\" valid8=\"false\" valid9=\"false\">1234</test>"
            )
        );
        readWriteStream.end();

        assertThat(hasCalledEndOnReadWriteStreamParentClass).isFalse();

        verify(policyChain, times(1)).streamFailWith(any(PolicyResult.class));
    }

    @Test
    public void shouldRejectWhenMaxChildrenExceeded() {
        configuration.setMaxChildrenPerElement(1);
        cut = new XmlThreatProtectionPolicy(configuration);
        ReadWriteStream<Buffer> readWriteStream = cut.onRequestContent(request, policyChain);

        assertThat(readWriteStream).isNotNull();
        final AtomicBoolean hasCalledEndOnReadWriteStreamParentClass = spyEndHandler(readWriteStream);

        readWriteStream.write(Buffer.buffer("<test><child1></child1><child2></child2></test>"));
        readWriteStream.end();

        assertThat(hasCalledEndOnReadWriteStreamParentClass).isFalse();

        verify(policyChain, times(1)).streamFailWith(any(PolicyResult.class));
    }

    @Test
    public void shouldRejectWhenMaxDepthExceeded() {
        configuration.setMaxDepth(1);
        cut = new XmlThreatProtectionPolicy(configuration);
        ReadWriteStream<Buffer> readWriteStream = cut.onRequestContent(request, policyChain);

        assertThat(readWriteStream).isNotNull();
        final AtomicBoolean hasCalledEndOnReadWriteStreamParentClass = spyEndHandler(readWriteStream);

        readWriteStream.write(Buffer.buffer("<test><child><subChild></subChild></child></test>"));
        readWriteStream.end();

        assertThat(hasCalledEndOnReadWriteStreamParentClass).isFalse();

        verify(policyChain, times(1)).streamFailWith(any(PolicyResult.class));
    }

    @Test
    public void shouldRejectWhenEntityMaxDepthExceeded() {
        configuration.setMaxEntityDepth(4);
        cut = new XmlThreatProtectionPolicy(configuration);
        ReadWriteStream<Buffer> readWriteStream = cut.onRequestContent(request, policyChain);

        assertThat(readWriteStream).isNotNull();
        final AtomicBoolean hasCalledEndOnReadWriteStreamParentClass = spyEndHandler(readWriteStream);

        readWriteStream.write(
            Buffer.buffer(
                "<!DOCTYPE test [\n" +
                "<!ENTITY lol \"lol\">\n" +
                "<!ENTITY lol2 \"&lol; &lol;\">\n" +
                "<!ENTITY lol3 \"&lol2; &lol2;\">\n" +
                "<!ENTITY lol4 \"&lol3; &lol3;\">\n" +
                "<!ENTITY lol5 \"&lol4; &lol4;\">\n" +
                "]>\n" +
                "<test>&lol5;</test>"
            )
        );
        readWriteStream.end();

        assertThat(hasCalledEndOnReadWriteStreamParentClass).isFalse();

        verify(policyChain, times(1)).streamFailWith(any(PolicyResult.class));
    }

    @Test
    public void shouldRejectWhenMaxEntitiesExceeded() {
        configuration.setMaxEntities(1);
        cut = new XmlThreatProtectionPolicy(configuration);
        ReadWriteStream<Buffer> readWriteStream = cut.onRequestContent(request, policyChain);

        assertThat(readWriteStream).isNotNull();
        final AtomicBoolean hasCalledEndOnReadWriteStreamParentClass = spyEndHandler(readWriteStream);

        readWriteStream.write(
            Buffer.buffer(
                "<!DOCTYPE test [\n" + "<!ENTITY lol \"lol\">\n" + "<!ENTITY lol2 \"&lol; &lol;\">\n" + "]>\n" + "<test>&lol2;</test>"
            )
        );
        readWriteStream.end();

        assertThat(hasCalledEndOnReadWriteStreamParentClass).isFalse();

        verify(policyChain, times(1)).streamFailWith(any(PolicyResult.class));
    }

    @Test
    public void shouldRejectWhenMaxElementsExceeded() {
        configuration.setMaxElements(2);
        cut = new XmlThreatProtectionPolicy(configuration);
        ReadWriteStream<Buffer> readWriteStream = cut.onRequestContent(request, policyChain);

        assertThat(readWriteStream).isNotNull();
        final AtomicBoolean hasCalledEndOnReadWriteStreamParentClass = spyEndHandler(readWriteStream);

        readWriteStream.write(Buffer.buffer("<test><element1 /><element2 /><element3 /></test>"));
        readWriteStream.end();

        assertThat(hasCalledEndOnReadWriteStreamParentClass).isFalse();

        verify(policyChain, times(1)).streamFailWith(any(PolicyResult.class));
    }

    @Test
    public void shouldRejectExternalEntities() {
        configuration.setAllowExternalEntities(false);
        cut = new XmlThreatProtectionPolicy(configuration);
        ReadWriteStream<Buffer> readWriteStream = cut.onRequestContent(request, policyChain);

        assertThat(readWriteStream).isNotNull();
        final AtomicBoolean hasCalledEndOnReadWriteStreamParentClass = spyEndHandler(readWriteStream);

        // Perform an injection of logback xml file.
        String path = getClass().getResource("/logback-test.xml").getPath();

        readWriteStream.write(
            Buffer.buffer(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                "<!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"file://" +
                path +
                "\"> ]>\n" +
                "<stockCheck><productId>&xxe;</productId></stockCheck>"
            )
        );
        readWriteStream.end();

        assertThat(hasCalledEndOnReadWriteStreamParentClass).isFalse();

        verify(policyChain, times(1)).streamFailWith(any(PolicyResult.class));
    }

    @Test
    public void shouldNotRejectExternalEntities() {
        configuration.setAllowExternalEntities(true);
        cut = new XmlThreatProtectionPolicy(configuration);
        ReadWriteStream<Buffer> readWriteStream = cut.onRequestContent(request, policyChain);

        assertThat(readWriteStream).isNotNull();
        final AtomicBoolean hasCalledEndOnReadWriteStreamParentClass = spyEndHandler(readWriteStream);

        int port = wireMockRule.port();
        stubFor(
            get(urlEqualTo("/evil.dtd"))
                .willReturn(
                    aResponse()
                        .withStatus(200)
                        .withBody("<!ENTITY % all \"<!ENTITY send SYSTEM 'http://localhost:" + port + "/collector'>\">" + "%all;")
                )
        );
        stubFor(get(urlEqualTo("/collector")).willReturn(aResponse().withStatus(200)));

        String path = getClass().getResource("/logback-test.xml").getPath();

        readWriteStream.write(
            Buffer.buffer(
                "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n" +
                "<!DOCTYPE data [\n" +
                "  <!ENTITY % file SYSTEM \"file://" +
                path +
                "\">\n" +
                "  <!ENTITY % dtd SYSTEM \"http://localhost:" +
                port +
                "/evil.dtd\">\n" +
                "  %dtd;\n" +
                "]>\n" +
                "<data></data>"
            )
        );

        readWriteStream.end();

        assertThat(hasCalledEndOnReadWriteStreamParentClass).isTrue();

        verify(0, getRequestedFor(urlEqualTo("/evil.dtd")));
        verify(0, getRequestedFor(urlEqualTo("/collector")));
        verifyNoInteractions(policyChain);
    }

    @Test
    public void shouldRejectExternalEntities_undeclaredEntity() {
        configuration.setAllowExternalEntities(true);
        cut = new XmlThreatProtectionPolicy(configuration);
        ReadWriteStream<Buffer> readWriteStream = cut.onRequestContent(request, policyChain);

        assertThat(readWriteStream).isNotNull();
        final AtomicBoolean hasCalledEndOnReadWriteStreamParentClass = spyEndHandler(readWriteStream);

        int port = wireMockRule.port();
        stubFor(
            get(urlEqualTo("/evil.dtd"))
                .willReturn(
                    aResponse()
                        .withStatus(200)
                        .withBody("<!ENTITY % all \"<!ENTITY send SYSTEM 'http://localhost:" + port + "/collector'>\">" + "%all;")
                )
        );
        stubFor(get(urlEqualTo("/collector")).willReturn(aResponse().withStatus(200)));

        String path = getClass().getResource("/logback-test.xml").getPath();

        readWriteStream.write(
            Buffer.buffer(
                "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n" +
                "<!DOCTYPE data [\n" +
                "  <!ENTITY % file SYSTEM \"file://" +
                path +
                "\">\n" +
                "  <!ENTITY % dtd SYSTEM \"http://localhost:" +
                port +
                "/evil.dtd\">\n" +
                "  %dtd;\n" +
                "]>\n" +
                "<data>&send;</data>"
            )
        );

        readWriteStream.end();

        assertThat(hasCalledEndOnReadWriteStreamParentClass).isFalse();
    }

    /**
     * Replace the endHandler of the resulting ReadWriteStream of the policy execution.
     * This endHandler will set an {@link AtomicBoolean} to {@code true} if its called.
     * It will allow us to verify if super.end() has been called on {@link BufferedReadWriteStream#end()}
     * @param readWriteStream: the {@link ReadWriteStream} to modify
     * @return an AtomicBoolean set to {@code true} if {@link SimpleReadWriteStream#end()}, else {@code false}
     */
    private AtomicBoolean spyEndHandler(ReadWriteStream readWriteStream) {
        final AtomicBoolean hasCalledEndOnReadWriteStreamParentClass = new AtomicBoolean(false);
        readWriteStream.endHandler(__ -> {
            hasCalledEndOnReadWriteStreamParentClass.set(true);
        });
        return hasCalledEndOnReadWriteStreamParentClass;
    }
}
