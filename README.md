# KeyBot / V2Ray Key Bot

[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/victorgeel/keybot/test-and-upload.yml?branch=main)](https://github.com/victorgeel/keybot/actions/workflows/test-and-upload.yml) [![Telegram Bot](https://img.shields.io/badge/Telegram%20Bot-@v2rayxray_bot-blue?logo=telegram&logoColor=white)](https://t.me/v2rayxray_bot)

This project automatically fetches, tests, and provides working V2Ray configuration keys (VMess, VLess, Trojan, SS) through a consolidated subscription link and a Telegram bot.

## Features

* Automated key testing using `xray-core`.
* Supports multiple protocols: VMess, VLess, Trojan, Shadowsocks (SS).
* Fetches keys from multiple sources defined via GitHub Secrets.
* Consolidates all working keys into a single file.
* Updates periodically via GitHub Actions (every 30 minutes).
* Provides keys via a direct subscription link and a Telegram Bot.

## How it Works

1.  A GitHub Actions workflow runs every 30 minutes based on a schedule (`cron`) or manual dispatch.
2.  The workflow checks out the repository code.
3.  It sets up Python and installs dependencies (`requests`).
4.  A Python script (`test_and_upload.py`) downloads the latest `xray-core` binary if needed.
5.  The script fetches key lists from URLs specified in the `SOURCE_URLS_SECRET` GitHub Action secret.
6.  Each potential key is tested for validity and connectivity using `xray run -test`.
7.  Working keys are collected, shuffled, and limited (currently to a maximum of `1500` keys).
8.  The consolidated list of working keys is saved to `subscription/working_keys.txt`.
9.  The workflow commits the updated file and force-pushes it back to the `main` branch of this repository using a `PUSH_TOKEN`.
10. The workflow installs `rclone`, configures it using R2 API credentials secrets, and uploads the `subscription/working_keys.txt` file to a configured Cloudflare R2 bucket.
11. A separate Cloudflare Worker hosts the Telegram bot ([@v2rayxray_bot](https://t.me/v2rayxray_bot)). This worker fetches the `working_keys.txt` file from R2's public URL and serves keys to users upon request.

## Subscription Link

You can use the following link directly in compatible V2Ray clients (like v2rayN, v2rayNG, Nekoray, etc.) to subscribe to the working keys:

https://raw.githubusercontent.com/victorgeel/keybot/main/subscription/working_keys.txt

This file contains all currently working keys (up to the defined limit of 1500) found and tested by the script during the last workflow run.

## Telegram Bot

A companion Telegram bot ([@v2rayxray_bot](https://t.me/v2rayxray_bot)) provides easy access to these keys. Interact with the bot using the following command:

* `/key <amount>`: Get a specified number of randomly selected working keys (e.g., `/key 50`). The maximum amount per request is 200.

Developed by: @VictorIsGeek

## Technology Stack

* GitHub Actions (CI/CD, Automation)
* Python 3 (Key fetching, Testing coordination)
* [Xray-core](https://github.com/XTLS/Xray-core) (Core testing engine)
* [rclone](https://rclone.org/) (R2 Uploader)
* Cloudflare R2 (Storage for key list used by the bot)
* Cloudflare Workers (Telegram Bot hosting)
* Telegram Bot API

## Setup (For Maintainers / Forking)

To run this workflow (e.g., in a fork of this repository), you need to configure the following GitHub Actions secrets in your repository settings (`Settings` > `Secrets and variables` > `Actions`):

* **`PUSH_TOKEN`**: A GitHub Personal Access Token (Classic or Fine-Grained) with `repo` scope permissions to allow pushing changes back to the repository.
* **`SOURCE_URLS_SECRET`**: A multiline string containing the source URLs for fetching keys, with one URL per line.
* **`R2_ACCESS_KEY_ID`**: Cloudflare R2 API Token Access Key ID with "Object Read & Write" permissions.
* **`R2_SECRET_ACCESS_KEY`**: Cloudflare R2 API Token Secret Access Key associated with the ID above.
* **`R2_BUCKET_NAME`**: The name of your Cloudflare R2 bucket where `working_keys.txt` will be uploaded.
* **`R2_ENDPOINT`**: Your Cloudflare R2 account-scoped S3 API endpoint (e.g., `https://<ACCOUNT_ID>.r2.cloudflarestorage.com`).

Additionally, the Telegram bot running on Cloudflare Workers requires its own environment variables/secrets (`TELEGRAM_BOT_TOKEN`, `R2_PUBLIC_BUCKET_URL`).

## Disclaimer

The keys provided by this project are sourced from publicly available lists on the internet. Their stability, speed, security, and longevity are not guaranteed. Using these keys may have associated risks depending on your location and use case. This project is intended for educational and experimental purposes. **Use these keys at your own risk.**

## Contributing

Contributions, issues, and feature requests are welcome! Please feel free to check [issues page](https://github.com/victorgeel/keybot/issues).

## License

(Optional: Add license information here if you choose one. E.g., MIT License)
