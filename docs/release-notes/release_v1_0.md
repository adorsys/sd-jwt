# SD-JWT Release Notes - Version 1.0

## Introduction:
SD-JWT is a Java library for handling Selective Disclosures JSON Web Tokens (JWTs) used in secure data exchange.

## What's Changed:

### Initial Setup:
- **Initialized Repository with Keycloak Core Clone:**
    - Cloned the initial version from Keycloak Core to begin the development of SD-JWT.
      [PR #1](https://github.com/adorsys/sd-jwt/pull/1)

### Features Added:
- **Implemented SD-JWT Verifiable Presentation:**
    - Added functionality to read and process verifiable presentations in SD-JWT format.
      [PR #1](https://github.com/adorsys/sd-jwt/pull/1)

- **Exposed extra verification:**
    - Implemented `exp` & `nbf` claims verification.
      [PR #2](https://github.com/adorsys/sd-jwt/pull/2)

### Dependency Changes:
- **Removed Keycloak Dependencies, Replaced with Nimbus Jose:**
    - Removed all dependencies on Keycloak and replaced them with Nimbus Jose library for JWT handling.
      [PR #3](https://github.com/adorsys/sd-jwt/pull/3)

## Full Changelog:

For a detailed list of all changes, please visit the [commit history](https://github.com/adorsys/sd-jwt/commits/1.0).
