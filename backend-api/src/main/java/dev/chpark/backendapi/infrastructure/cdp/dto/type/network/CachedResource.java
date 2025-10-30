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

import io.webfolder.cdp.type.page.ResourceType;

/**
 * Information about the cached resource
 */
public class CachedResource {
    private String url;

    private ResourceType type;

    private Response response;

    private Double bodySize;

    /**
     * Resource URL. This is the url of the original network request.
     */
    public String getUrl() {
        return url;
    }

    /**
     * Resource URL. This is the url of the original network request.
     */
    public void setUrl(String url) {
        this.url = url;
    }

    /**
     * Type of this resource.
     */
    public ResourceType getType() {
        return type;
    }

    /**
     * Type of this resource.
     */
    public void setType(ResourceType type) {
        this.type = type;
    }

    /**
     * Cached response data.
     */
    public Response getResponse() {
        return response;
    }

    /**
     * Cached response data.
     */
    public void setResponse(Response response) {
        this.response = response;
    }

    /**
     * Cached response body size.
     */
    public Double getBodySize() {
        return bodySize;
    }

    /**
     * Cached response body size.
     */
    public void setBodySize(Double bodySize) {
        this.bodySize = bodySize;
    }
}
