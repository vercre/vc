import * as st from 'shared_types/types/shared_types';

export const request = async ({
    url,
    method,
    headers,
}: st.HttpRequest): Promise<st.HttpResult> => {
    const request = new Request(url, {
        method,
        headers: headers.map((header) => [header.name, header.value]),
    });
    console.log('http request:', request);

    const response = await fetch(request);
    console.log('http response:', response);

    const responseHeaders: st.HttpHeader[] = Array.from(
        response.headers.entries(),
        ([name, value]) => new st.HttpHeader(name, value),
    );

    const body = await response.arrayBuffer();
    console.log('http response body:', body);

    return new st.HttpResultVariantOk(
        new st.HttpResponse(
            response.status,
            responseHeaders,
            Array.from(new Uint8Array(body)),
        )
    );
};
