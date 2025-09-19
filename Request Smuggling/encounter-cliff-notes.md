Encounter Cliff Notes

- CL.TE smuggling
  - Front-end used Content-Length; back-end honored chunked. Sent `Content-Length` with `Transfer-Encoding: chunked` and crafted body to smuggle a `GET /404` request that the back-end processed.

- TE.CL smuggling
  - Front-end used chunked; back-end used Content-Length. Sent chunked body containing a second request so back-end parsed extra bytes as next request.


