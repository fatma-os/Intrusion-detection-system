# Publish AIRGUARD to GitHub

1. Create an empty repository in GitHub. Leave the README, license, and .gitignore options unchecked.
2. Open PowerShell in this folder (`outputs`).
3. Copy the Git commands in the **Publish the code to GitHub** section of `README.md`, replacing the username and repository placeholders.
4. Authenticate when GitHub prompts you.
5. For later changes, run `git add .`, `git commit -m "Describe your update"`, and `git push`.

The `.gitignore` keeps generated alert logs, captures, Python bytecode, and virtual environments out of version control. Do not publish private captures or credentials.
