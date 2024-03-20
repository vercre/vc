import * as st from 'shared_types/types/shared_types';

export const request = async ({
    url,
    method,
    headers,
    body,
}: st.HttpRequest): Promise<st.HttpResult> => {
    const request = new Request(url, {
        method,
        headers: headers.map((header) => [header.name, header.value]),
        body: body && method === 'POST' ? new Uint8Array(body) : undefined,
    });
    console.log('http request:', request);

    const response = await fetch(request);
    console.log('http response:', response);

    const responseHeaders: st.HttpHeader[] = Array.from(
        response.headers.entries(),
        ([name, value]) => new st.HttpHeader(name, value),
    );

    const resBody = await response.arrayBuffer();
    const bodyBytes = new Uint8Array(resBody);
    var debug = new TextDecoder().decode(bodyBytes);
    console.log('http response body:', debug);

    return new st.HttpResultVariantOk(
        new st.HttpResponse(
            response.status,
            responseHeaders,
            Array.from(bodyBytes),
        )
    );
};
