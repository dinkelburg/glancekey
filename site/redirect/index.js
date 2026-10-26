export default {
  fetch(request) {
    const url = new URL(request.url);
    url.protocol = "https:";
    url.host = "www.glancekey.com";
    return Response.redirect(url.toString(), 301);
  },
};
