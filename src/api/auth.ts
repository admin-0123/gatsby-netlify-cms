// export { auth as default } from '@openlab/vercel-netlify-cms-github'

import dedent from 'dedent'
import { NowRequest, NowResponse } from '@vercel/node'
import { randomBytes } from 'crypto'
import { AuthorizationCode, ModuleOptions } from 'simple-oauth2'

const {
  OAUTH_HOST = 'https://github.com',
  OAUTH_TOKEN_PATH = '/login/oauth/access_token',
  OAUTH_AUTHORIZE_PATH = '/login/oauth/authorize',
} = process.env

const GATSBY_OAUTH_CLIENT_ID = process.env.GATSBY_OAUTH_CLIENT_ID;
const GATSBY_OAUTH_CLIENT_SECRET = process.env.GATSBY_OAUTH_CLIENT_SECRET;



export const oauthConfig: ModuleOptions = Object.freeze({
  client: Object.freeze({
    id: GATSBY_OAUTH_CLIENT_ID!,
    secret: GATSBY_OAUTH_CLIENT_SECRET,
  }),
  auth: Object.freeze({
    tokenHost: OAUTH_HOST,
    tokenPath: OAUTH_TOKEN_PATH,
    authorizePath: OAUTH_AUTHORIZE_PATH,
  }),
})

export function randomState() {
  return randomBytes(6).toString('hex')
}

/** Render a html response with a script to finish a client-side github authentication */
export function renderResponse(status: 'success' | 'error', content: any) {
  return dedent`
  <!DOCTYPE html>
  <html lang="en">
    <head>
      <meta charset="utf-8">
      <title>Authorizing ...</title>
    </head>
    <body>
      <p id="message"></p>
      <script>
        // Output a message to the user
        function sendMessage(message) {
          document.getElementById("message").innerText = message;
          document.title = message
        }

        // Handle a window message by sending the auth to the "opener"
        function receiveMessage(message) {
          console.debug("receiveMessage", message);
          window.opener.postMessage(
            'authorization:github:${status}:${JSON.stringify(content)}',
            message.origin
          );
          window.removeEventListener("message", receiveMessage, false);
          sendMessage("Authorized, closing ...");
        }

        sendMessage("Authorizing ...");
        window.addEventListener("message", receiveMessage, false);

        console.debug("postMessage", "authorizing:github", "*")
        window.opener.postMessage("authorizing:github", "*");
      </script>
    </body>
  </html>
  `
}

/** An endpoint to start an OAuth2 authentication */
export default function auth(req: any, res: any) {
  console.log("auth", req)
  const { host } = req.headers
  console.log('host', host)
  console.debug('auth host=%o', host)

  const authorizationCode = new AuthorizationCode(oauthConfig)

  const url = authorizationCode.authorizeURL({
    redirect_uri: `https://${host}/api/callback`,
    scope: `repo,user`,
    state: randomState(),
  })

  res.writeHead(301, { Location: url })
  res.end()
}

