/**
 * The MIT License
 * Copyright © 2017 WebFolder OÜ
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package dev.chpark.backendapi.infrastructure.cdp.dto.type.network;

import java.util.ArrayList;
import java.util.List;

/**
 * Security details about a request
 */
public class SecurityDetails {
    private String protocol;

    private String keyExchange;

    private String keyExchangeGroup;

    private String cipher;

    private String mac;

    private Integer certificateId;

    private String subjectName;

    private List<String> sanList = new ArrayList<>();

    private String issuer;

    private Double validFrom;

    private Double validTo;

    private List<SignedCertificateTimestamp> signedCertificateTimestampList = new ArrayList<>();

    /**
     * Protocol name (e.g. "TLS 1.2" or "QUIC").
     */
    public String getProtocol() {
        return protocol;
    }

    /**
     * Protocol name (e.g. "TLS 1.2" or "QUIC").
     */
    public void setProtocol(String protocol) {
        this.protocol = protocol;
    }

    /**
     * Key Exchange used by the connection, or the empty string if not applicable.
     */
    public String getKeyExchange() {
        return keyExchange;
    }

    /**
     * Key Exchange used by the connection, or the empty string if not applicable.
     */
    public void setKeyExchange(String keyExchange) {
        this.keyExchange = keyExchange;
    }

    /**
     * (EC)DH group used by the connection, if applicable.
     */
    public String getKeyExchangeGroup() {
        return keyExchangeGroup;
    }

    /**
     * (EC)DH group used by the connection, if applicable.
     */
    public void setKeyExchangeGroup(String keyExchangeGroup) {
        this.keyExchangeGroup = keyExchangeGroup;
    }

    /**
     * Cipher name.
     */
    public String getCipher() {
        return cipher;
    }

    /**
     * Cipher name.
     */
    public void setCipher(String cipher) {
        this.cipher = cipher;
    }

    /**
     * TLS MAC. Note that AEAD ciphers do not have separate MACs.
     */
    public String getMac() {
        return mac;
    }

    /**
     * TLS MAC. Note that AEAD ciphers do not have separate MACs.
     */
    public void setMac(String mac) {
        this.mac = mac;
    }

    /**
     * Certificate ID value.
     */
    public Integer getCertificateId() {
        return certificateId;
    }

    /**
     * Certificate ID value.
     */
    public void setCertificateId(Integer certificateId) {
        this.certificateId = certificateId;
    }

    /**
     * Certificate subject name.
     */
    public String getSubjectName() {
        return subjectName;
    }

    /**
     * Certificate subject name.
     */
    public void setSubjectName(String subjectName) {
        this.subjectName = subjectName;
    }

    /**
     * Subject Alternative Name (SAN) DNS names and IP addresses.
     */
    public List<String> getSanList() {
        return sanList;
    }

    /**
     * Subject Alternative Name (SAN) DNS names and IP addresses.
     */
    public void setSanList(List<String> sanList) {
        this.sanList = sanList;
    }

    /**
     * Name of the issuing CA.
     */
    public String getIssuer() {
        return issuer;
    }

    /**
     * Name of the issuing CA.
     */
    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    /**
     * Certificate valid from date.
     */
    public Double getValidFrom() {
        return validFrom;
    }

    /**
     * Certificate valid from date.
     */
    public void setValidFrom(Double validFrom) {
        this.validFrom = validFrom;
    }

    /**
     * Certificate valid to (expiration) date
     */
    public Double getValidTo() {
        return validTo;
    }

    /**
     * Certificate valid to (expiration) date
     */
    public void setValidTo(Double validTo) {
        this.validTo = validTo;
    }

    /**
     * List of signed certificate timestamps (SCTs).
     */
    public List<SignedCertificateTimestamp> getSignedCertificateTimestampList() {
        return signedCertificateTimestampList;
    }

    /**
     * List of signed certificate timestamps (SCTs).
     */
    public void setSignedCertificateTimestampList(List<SignedCertificateTimestamp> signedCertificateTimestampList) {
        this.signedCertificateTimestampList = signedCertificateTimestampList;
    }
}
