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

/**
 * Timing information for the request
 */
public class ResourceTiming {
    private Double requestTime;

    private Double proxyStart;

    private Double proxyEnd;

    private Double dnsStart;

    private Double dnsEnd;

    private Double connectStart;

    private Double connectEnd;

    private Double sslStart;

    private Double sslEnd;

    private Double workerStart;

    private Double workerReady;

    private Double sendStart;

    private Double sendEnd;

    private Double pushStart;

    private Double pushEnd;

    private Double receiveHeadersEnd;

    /**
     * Timing's requestTime is a baseline in seconds, while the other numbers are ticks in milliseconds relatively to this requestTime.
     */
    public Double getRequestTime() {
        return requestTime;
    }

    /**
     * Timing's requestTime is a baseline in seconds, while the other numbers are ticks in milliseconds relatively to this requestTime.
     */
    public void setRequestTime(Double requestTime) {
        this.requestTime = requestTime;
    }

    /**
     * Started resolving proxy.
     */
    public Double getProxyStart() {
        return proxyStart;
    }

    /**
     * Started resolving proxy.
     */
    public void setProxyStart(Double proxyStart) {
        this.proxyStart = proxyStart;
    }

    /**
     * Finished resolving proxy.
     */
    public Double getProxyEnd() {
        return proxyEnd;
    }

    /**
     * Finished resolving proxy.
     */
    public void setProxyEnd(Double proxyEnd) {
        this.proxyEnd = proxyEnd;
    }

    /**
     * Started DNS address resolve.
     */
    public Double getDnsStart() {
        return dnsStart;
    }

    /**
     * Started DNS address resolve.
     */
    public void setDnsStart(Double dnsStart) {
        this.dnsStart = dnsStart;
    }

    /**
     * Finished DNS address resolve.
     */
    public Double getDnsEnd() {
        return dnsEnd;
    }

    /**
     * Finished DNS address resolve.
     */
    public void setDnsEnd(Double dnsEnd) {
        this.dnsEnd = dnsEnd;
    }

    /**
     * Started connecting to the remote host.
     */
    public Double getConnectStart() {
        return connectStart;
    }

    /**
     * Started connecting to the remote host.
     */
    public void setConnectStart(Double connectStart) {
        this.connectStart = connectStart;
    }

    /**
     * Connected to the remote host.
     */
    public Double getConnectEnd() {
        return connectEnd;
    }

    /**
     * Connected to the remote host.
     */
    public void setConnectEnd(Double connectEnd) {
        this.connectEnd = connectEnd;
    }

    /**
     * Started SSL handshake.
     */
    public Double getSslStart() {
        return sslStart;
    }

    /**
     * Started SSL handshake.
     */
    public void setSslStart(Double sslStart) {
        this.sslStart = sslStart;
    }

    /**
     * Finished SSL handshake.
     */
    public Double getSslEnd() {
        return sslEnd;
    }

    /**
     * Finished SSL handshake.
     */
    public void setSslEnd(Double sslEnd) {
        this.sslEnd = sslEnd;
    }

    /**
     * Started running ServiceWorker.
     */
    public Double getWorkerStart() {
        return workerStart;
    }

    /**
     * Started running ServiceWorker.
     */
    public void setWorkerStart(Double workerStart) {
        this.workerStart = workerStart;
    }

    /**
     * Finished Starting ServiceWorker.
     */
    public Double getWorkerReady() {
        return workerReady;
    }

    /**
     * Finished Starting ServiceWorker.
     */
    public void setWorkerReady(Double workerReady) {
        this.workerReady = workerReady;
    }

    /**
     * Started sending request.
     */
    public Double getSendStart() {
        return sendStart;
    }

    /**
     * Started sending request.
     */
    public void setSendStart(Double sendStart) {
        this.sendStart = sendStart;
    }

    /**
     * Finished sending request.
     */
    public Double getSendEnd() {
        return sendEnd;
    }

    /**
     * Finished sending request.
     */
    public void setSendEnd(Double sendEnd) {
        this.sendEnd = sendEnd;
    }

    /**
     * Time the server started pushing request.
     */
    public Double getPushStart() {
        return pushStart;
    }

    /**
     * Time the server started pushing request.
     */
    public void setPushStart(Double pushStart) {
        this.pushStart = pushStart;
    }

    /**
     * Time the server finished pushing request.
     */
    public Double getPushEnd() {
        return pushEnd;
    }

    /**
     * Time the server finished pushing request.
     */
    public void setPushEnd(Double pushEnd) {
        this.pushEnd = pushEnd;
    }

    /**
     * Finished receiving response headers.
     */
    public Double getReceiveHeadersEnd() {
        return receiveHeadersEnd;
    }

    /**
     * Finished receiving response headers.
     */
    public void setReceiveHeadersEnd(Double receiveHeadersEnd) {
        this.receiveHeadersEnd = receiveHeadersEnd;
    }
}
