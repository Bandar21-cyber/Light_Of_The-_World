# Volunteer Roster: Netlify setup

This folder is the whole site:

- `index.html`: the roster, sign-up forms and admin tools
- `netlify/functions/signups.mjs`: server code for admin login, admin accounts, the shared roster, and pulling sign-ups from Netlify Forms
- `package.json`: tells Netlify to install `@netlify/blobs`, where admin accounts and the shared roster are stored
- `assets/`: the Light the World logo (header and login) and the Giving Machine photo (sign-up form)
- `netlify.toml`: tells Netlify where the site and function are, to use Node 22, and to serve the admin login at `/admin`

The roster (volunteers, assignments and shift sizes) is stored on the server in Netlify Blobs and shared by all admins. Changes save automatically; other admins' changes appear within a minute. Sign-ups sync into the roster automatically every minute while an admin is logged in.

## One-time setup

1. **Deploy with Git or the Netlify CLI, not drag-and-drop.** Drag-and-drop doesn't deploy functions.
   - Git: put this folder's contents in a GitHub repo, then in Netlify choose **Add new site > Import an existing project** and pick the repo. Leave the build command empty.
   - CLI: from this folder run `npx netlify-cli deploy --prod`.
2. **Create an access token:** in Netlify, click your avatar > **User settings > Applications > Personal access tokens > New access token**. Copy it.
3. **Add it to the site:** **Site configuration > Environment variables > Add a variable**. Key `NETLIFY_API_TOKEN`, value = the token. Scope it to Functions.
4. **Turn on form detection:** **Site configuration > Forms > Enable form detection**.
5. **Redeploy** so the token and form are picked up (Deploys > Trigger deploy).
6. Submit a test sign-up, log in as an admin, and click **Sync now**. The test person should appear.

## Admin accounts

Admins log in at `https://<your-site>.netlify.app/admin`. The public pages (`/`, `/#signup`, `/#ward-signup`) have no admin button.


Any admin can add or remove admins, and change their own password, on the **Admins** tab. These accounts are stored in Netlify Blobs and take effect immediately, with no redeploy.

The three built-in admins are listed in both `CONFIG.admins` in `index.html` and `BUILT_IN_ADMINS` in `netlify/functions/signups.mjs`. They can't be removed in the app. If the server can't be reached, only the built-in admins can log in, using their original passwords.

Keep the access token private. It is only ever read on the server.
