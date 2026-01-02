#!/usr/bin/env python3
#
#  This file is licensed under the MIT license
#  This file originates from https://github.com/caseychu/spotify-backup

import codecs
import http.client
import http.server
#!/usr/bin/env python3
#
#  This file is licensed under the MIT license
#  This file originates from https://github.com/caseychu/spotify-backup

import codecs
import http.client
import http.server
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
import os
import base64
import logging


class SpotifyAPI:
    """Class to interact with the Spotify API using an OAuth token."""

    BASE_URL = "https://api.spotify.com/v1/"
    # Keep track of the last client_id used to start authorization so
    # the handler can use it for token exchange if env var is missing.
    _LAST_CLIENT_ID = None

    def __init__(self, auth):
        self._auth = auth

    def get(self, url, params={}, tries=3):
        """Fetch a resource from Spotify API."""
        url = self._construct_url(url, params)
        for _ in range(tries):
            try:
                req = self._create_request(url)
                return self._read_response(req)
            except Exception as err:
                print(f"Error fetching URL {url}: {err}")
                time.sleep(2)
        sys.exit("Failed to fetch data from Spotify API after retries.")

    def list(self, url, params={}):
        """Fetch paginated resources and return as a combined list."""
        response = self.get(url, params)
        items = response["items"]

        while response["next"]:
            response = self.get(response["next"])
            items += response["items"]
        return items

    @staticmethod
    def authorize(client_id, scope):
        """Open a browser for user authorization and return SpotifyAPI instance."""
        redirect_uri = f"http://127.0.0.1:{SpotifyAPI._SERVER_PORT}/redirect"
        url = SpotifyAPI._construct_auth_url(client_id, scope, redirect_uri)
        print(f"Open this link if the browser doesn't open automatically: {url}")
        webbrowser.open(url)

        # remember client_id so the request handler can reuse it for token exchange
        SpotifyAPI._LAST_CLIENT_ID = client_id
        server = SpotifyAPI._AuthorizationServer("127.0.0.1", SpotifyAPI._SERVER_PORT)
        try:
            while True:
                server.handle_request()
        except SpotifyAPI._Authorization as auth:
            return SpotifyAPI(auth.access_token)

    @staticmethod
    def _construct_auth_url(client_id, scope, redirect_uri):
        # Use authorization code flow. The server will exchange the code for a token.
        return "https://accounts.spotify.com/authorize?" + urllib.parse.urlencode(
            {
                "response_type": "code",
                "client_id": client_id,
                "scope": scope,
                "redirect_uri": redirect_uri,
            }
        )

    def _construct_url(self, url, params):
        """Construct a full API URL."""
        if not url.startswith(self.BASE_URL):
            url = self.BASE_URL + url
        if params:
            url += ("&" if "?" in url else "?") + urllib.parse.urlencode(params)
        return url

    def _create_request(self, url):
        """Create an authenticated request."""
        req = urllib.request.Request(url)
        req.add_header("Authorization", f"Bearer {self._auth}")
        return req

    def _read_response(self, req):
        """Read and parse the response."""
        with urllib.request.urlopen(req) as res:
            reader = codecs.getreader("utf-8")
            return json.load(reader(res))

    _SERVER_PORT = 43019

    class _AuthorizationServer(http.server.HTTPServer):
        def __init__(self, host, port):
            super().__init__((host, port), SpotifyAPI._AuthorizationHandler)

        def handle_error(self, request, client_address):
            raise

    class _AuthorizationHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path.startswith("/redirect"):
                self._redirect_to_token()
            elif self.path.startswith("/token?"):
                self._handle_token()
            else:
                self.send_error(404)

        def _redirect_to_token(self):
            # If the redirect contains a query (e.g. ?code=...), handle it here.
            parsed = urllib.parse.urlparse(self.path)
            qs = urllib.parse.parse_qs(parsed.query)
            if "code" in qs:
                code = qs["code"][0]
                # Exchange authorization code for access token.
                client_secret = os.environ.get("SPOTIFY_CLIENT_SECRET")
                client_id = os.environ.get("SPOTIFY_CLIENT_ID") or SpotifyAPI._LAST_CLIENT_ID
                if not client_secret or not client_id:
                    print(
                        "Received authorization code, but SPOTIFY_CLIENT_SECRET or SPOTIFY_CLIENT_ID is not set.\n"
                        "Set environment variables SPOTIFY_CLIENT_ID and SPOTIFY_CLIENT_SECRET to enable code exchange.\n"
                        "Authorization code: %s" % code
                    )
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html")
                    self.end_headers()
                    self.wfile.write(b"Missing client credentials; check server logs.")
                    raise SpotifyAPI._Authorization(None)

                token_url = "https://accounts.spotify.com/api/token"
                post_data = urllib.parse.urlencode(
                    {
                        "grant_type": "authorization_code",
                        "code": code,
                        "redirect_uri": f"http://127.0.0.1:{SpotifyAPI._SERVER_PORT}/redirect",
                    }
                ).encode()

                auth_header = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
                req = urllib.request.Request(token_url, data=post_data)
                req.add_header("Authorization", f"Basic {auth_header}")
                req.add_header("Content-Type", "application/x-www-form-urlencoded")

                try:
                    with urllib.request.urlopen(req) as res:
                        body = json.load(res)
                        access_token = body.get("access_token")
                        if access_token:
                            print("Exchanged code for access token successfully.")
                            self.send_response(200)
                            self.send_header("Content-Type", "text/html")
                            self.end_headers()
                            self.wfile.write(b"<script>close()</script>Thanks! You may now close this window.")
                            raise SpotifyAPI._Authorization(access_token)
                        else:
                            logging.error("Token exchange did not return access_token: %s", body)
                            self.send_response(200)
                            self.send_header("Content-Type", "text/html")
                            self.end_headers()
                            self.wfile.write(b"Token exchange failed; check server logs.")
                            raise SpotifyAPI._Authorization(None)
                except urllib.error.HTTPError as e:
                    try:
                        err_body = e.read().decode()
                    except Exception:
                        err_body = "<unable to read error body>"
                    logging.error("Token exchange HTTPError %s: %s", e.code, err_body)
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html")
                    self.end_headers()
                    self.wfile.write(b"Token exchange failed; check server logs.")
                    raise SpotifyAPI._Authorization(None)
                except Exception as e:
                    logging.exception("Failed to exchange authorization code for token: %s", e)
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html")
                    self.end_headers()
                    self.wfile.write(b"Token exchange failed; check server logs.")
                    raise SpotifyAPI._Authorization(None)

            # No code in query — handle implicit-flow fragment transfer.
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b'<script>location.replace("token?" + location.hash.slice(1));</script>')

        def _handle_token(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(
                b"<script>close()</script>Thanks! You may now close this window."
            )
            # Safely parse the callback path for an access token or authorization code.
            path = self.path or ""
            # Log the raw callback path for debugging (printed to stdout).
            print(f"OAuth callback path: {path}")

            m = re.search(r"access_token=([^&]*)", path)
            if m:
                access_token = urllib.parse.unquote(m.group(1))
                raise SpotifyAPI._Authorization(access_token)

            # If an authorization code was returned instead, capture it and perform exchange.
            m = re.search(r"code=([^&]*)", path)
            if m:
                code = urllib.parse.unquote(m.group(1))
                client_secret = os.environ.get("SPOTIFY_CLIENT_SECRET")
                client_id = os.environ.get("SPOTIFY_CLIENT_ID") or SpotifyAPI._LAST_CLIENT_ID
                if not client_secret or not client_id:
                    print(
                        "Received authorization code, but SPOTIFY_CLIENT_SECRET or SPOTIFY_CLIENT_ID is not set.\n"
                        "Set environment variables SPOTIFY_CLIENT_ID and SPOTIFY_CLIENT_SECRET to enable code exchange.\n"
                        "Authorization code: %s" % code
                    )
                    raise SpotifyAPI._Authorization(None)

                token_url = "https://accounts.spotify.com/api/token"
                post_data = urllib.parse.urlencode(
                    {
                        "grant_type": "authorization_code",
                        "code": code,
                        "redirect_uri": f"http://127.0.0.1:{SpotifyAPI._SERVER_PORT}/redirect",
                    }
                ).encode()

                auth_header = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
                req = urllib.request.Request(token_url, data=post_data)
                req.add_header("Authorization", f"Basic {auth_header}")
                req.add_header(
                    "Content-Type", "application/x-www-form-urlencoded"
                )

                try:
                    with urllib.request.urlopen(req) as res:
                        body = json.load(res)
                        access_token = body.get("access_token")
                        if access_token:
                            print("Exchanged code for access token successfully.")
                            raise SpotifyAPI._Authorization(access_token)
                        else:
                            logging.error("Token exchange did not return access_token: %s", body)
                            raise SpotifyAPI._Authorization(None)
                except urllib.error.HTTPError as e:
                    try:
                        err_body = e.read().decode()
                    except Exception:
                        err_body = "<unable to read error body>"
                    logging.error("Token exchange HTTPError %s: %s", e.code, err_body)
                    raise SpotifyAPI._Authorization(None)
                except Exception as e:
                    logging.exception("Failed to exchange authorization code for token: %s", e)
                    raise SpotifyAPI._Authorization(None)

            # No token or code found in callback — log and raise to avoid AttributeError.
            print(f"OAuth callback contained no token or code: {path}")
            raise SpotifyAPI._Authorization(None)

        def log_message(self, format, *args):
            pass

    class _Authorization(Exception):
        def __init__(self, access_token):
            self.access_token = access_token


def fetch_user_data(spotify, dump):
    """Fetch playlists and liked songs based on the dump parameter."""
    playlists = []
    liked_albums = []

    if "liked" in dump:
        print("Loading liked albums and songs...")
        liked_tracks = spotify.list("me/tracks", {"limit": 50})
        liked_albums = spotify.list("me/albums", {"limit": 50})
        playlists.append({"name": "Liked Songs", "tracks": liked_tracks})

    if "playlists" in dump:
        print("Loading playlists...")
        playlist_data = spotify.list("me/playlists", {"limit": 50})
        for playlist in playlist_data:
            print(f"Loading playlist: {playlist['name']}")
            playlist["tracks"] = spotify.list(
                playlist["tracks"]["href"], {"limit": 100}
            )
        playlists.extend(playlist_data)

    return playlists, liked_albums


def write_to_file(file, format, playlists, liked_albums):
    """Write fetched data to a file in the specified format."""
    print(f"Writing to {file}...")
    with open(file, "w", encoding="utf-8") as f:
        if format == "json":
            json.dump({"playlists": playlists, "albums": liked_albums}, f)
        else:
            for playlist in playlists:
                f.write(playlist["name"] + "\r\n")
                for track in playlist["tracks"]:
                    if track["track"]:
                        f.write(
                            "{name}\t{artists}\t{album}\t{uri}\t{release_date}\r\n".format(
                                uri=track["track"]["uri"],
                                name=track["track"]["name"],
                                artists=", ".join([
                                    artist["name"] for artist in track["track"]["artists"]
                                ]),
                                album=track["track"]["album"]["name"],
                                release_date=track["track"]["album"]["release_date"],
                            )
                        )
                f.write("\r\n")


def main(dump="playlists,liked", format="json", file="playlists.json", token=""):
    print("Starting backup...")
    spotify = (
        SpotifyAPI(token)
        if token
        else SpotifyAPI.authorize(
            client_id="5c098bcc800e45d49e476265bc9b6934",
            scope="playlist-read-private playlist-read-collaborative user-library-read",
        )
    )

    playlists, liked_albums = fetch_user_data(spotify, dump)
    write_to_file(file, format, playlists, liked_albums)
    print(f"Backup completed! Data written to {file}")


if __name__ == "__main__":
    main()
