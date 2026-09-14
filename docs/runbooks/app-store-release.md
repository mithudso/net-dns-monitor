# Runbook: Mac App Store release

A per-release checklist. [APP_STORE_SUBMISSION.md](../APP_STORE_SUBMISSION.md) is
the authoritative document; each step links the section that holds the commands
and the details.

## When to use

Every upload of a new build to App Store Connect.

## Preconditions

- The one-time Apple setup is done: bundle identifier, App ID, both certificates,
  provisioning profile, app record and API key
  ([§3](../APP_STORE_SUBMISSION.md#3-one-time-apple-setup)).
- The build environment exists ([§4](../APP_STORE_SUBMISSION.md#4-build)).
- The privacy policy is hosted at an `https` URL with no placeholder left in it.
  The release build refuses otherwise
  ([§4.2](../APP_STORE_SUBMISSION.md#42-release-build)).
- **UNVERIFIED:** release mode has never run on this Mac, which has no Apple
  Distribution or Mac Installer Distribution certificate
  ([§2](../APP_STORE_SUBMISSION.md#2-what-is-already-done-in-this-repo)).

## Checklist

1. **Choose the version and build number.** Increase `--build-number` for every
   upload. App Store Connect rejects a build number reused for the same version.
   Change `--version` for a new release
   ([§4.2](../APP_STORE_SUBMISSION.md#42-release-build),
   [§9](../APP_STORE_SUBMISSION.md#9-every-upload)).
2. **Run the tests.** The suite must pass with no failures:

   ```bash
   .venv/bin/python -m pytest -q
   ```

3. **Build ad hoc and run the sandbox probe.** If the probe output differs from
   the feature table, update the table before you continue
   ([§4.1](../APP_STORE_SUBMISSION.md#41-ad-hoc-build-and-sandbox-probe-no-apple-account-needed),
   [§1](../APP_STORE_SUBMISSION.md#1-read-this-first-what-the-store-build-can-and-cannot-do)).
4. **Open the ad-hoc GUI app by hand.** Quit your normal copy first. Follow the
   "How to review" steps in the review notes
   ([§6.6](../APP_STORE_SUBMISSION.md#66-app-review-information)) and confirm each
   one works. Confirm that every feature marked "no" for the store build in
   [§1](../APP_STORE_SUBMISSION.md#1-read-this-first-what-the-store-build-can-and-cannot-do)
   is hidden or reports that it is unavailable. No automation can launch the app.
5. **Build for release** with `build_appstore.py release` and the chosen
   `--version` and `--build-number`. Add `--declare-exempt-encryption` only after
   answering export compliance
   ([§4.2](../APP_STORE_SUBMISSION.md#42-release-build),
   [§6.5](../APP_STORE_SUBMISSION.md#65-export-compliance)).
6. **Validate** the `.pkg` with `xcrun altool --validate-app`
   ([§5](../APP_STORE_SUBMISSION.md#5-validate-and-upload)).
7. **Upload** with `xcrun altool --upload-package ... --wait`, or with
   Transporter. Wait for processing, then install the build from TestFlight
   ([§5](../APP_STORE_SUBMISSION.md#5-validate-and-upload)).
8. **Update the metadata** that changed, including "What's New"
   ([§6.4](../APP_STORE_SUBMISSION.md#64-version-information-10)).
9. **Submit.** Add the build to the version, then Add for Review and Submit to App
   Review ([§7](../APP_STORE_SUBMISSION.md#7-submit)).

## Verify

- Validation in step 6 reports no errors.
- The build appears under the app's TestFlight tab and installs.
- The version's status in App Store Connect reads "Waiting for Review" after
  step 9.

## Roll back

- Before you submit: select a different build for the version, or fix the problem
  and upload a new build with a higher build number.
- After you submit, before review ends: remove the submission from review in App
  Store Connect, then upload a fixed build with a higher build number.
- After a rejection: answer in Resolution Center. Rejection risks and their
  mitigations are in [§8](../APP_STORE_SUBMISSION.md#8-rejection-risks-and-what-to-do).
- A build number cannot be reused. Every retry needs a new one.
