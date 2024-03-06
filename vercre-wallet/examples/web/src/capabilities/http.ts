import { HttpHeader, HttpRequest, HttpResponse } from "shared_types/types/shared_types";

export const request = async ({
    url,
    method,
    headers,
}: HttpRequest): Promise<HttpResponse> => {
    const request = new Request(url, {
        method,
        headers: headers.map((header) => [header.name, header.value]),
    });

    const response = await fetch(request);

    const responseHeaders: HttpHeader[] = Array.from(
        response.headers.entries(),
        ([name, value]) => new HttpHeader(name, value),
    );

    const body = await response.arrayBuffer();

    return new HttpResponse(
        response.status,
        responseHeaders,
        Array.from(new Uint8Array(body)),
    );
};
