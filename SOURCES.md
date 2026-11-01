# Sources

All pages were read on **2026-11-01**. If Microsoft or MITRE has changed a page
since then, the page wins over this repo.

## Log Analytics / Sentinel tables

| Item used | Source |
|---|---|
| `SigninLogs`: TimeGenerated, UserPrincipalName, UserId, IPAddress, Location, LocationDetails (dynamic), ResultType (string), ResultDescription, Status (dynamic), AuthenticationDetails, AuthenticationRequirement, AuthenticationProtocol, ClientAppUsed, AppDisplayName, AppId, UserAgent, ConditionalAccessStatus, RiskLevelDuringSignIn, RiskLevelAggregated, RiskState, RiskDetail, RiskEventTypes_V2, SessionId, AutonomousSystemNumber, CorrelationId; AuthenticationProtocol values include `deviceCode` | https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs |
| `AADNonInteractiveUserSignInLogs`: same core columns; LocationDetails, DeviceDetail, Status are **string**; AuthenticationProtocol includes `deviceCode` | https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadnoninteractiveusersigninlogs |
| `AuditLogs`: TimeGenerated, OperationName, Category, InitiatedBy (dynamic), TargetResources (dynamic), AdditionalDetails, Result, ResultReason, CorrelationId | https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/auditlogs |
| `AADUserRiskEvents`: TimeGenerated, ActivityDateTime, DetectedDateTime, UserPrincipalName, UserId, RiskEventType, RiskLevel, RiskState, RiskDetail, DetectionTimingType, Source, IpAddress, Location, CorrelationId, RequestId | https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aaduserriskevents |
| `OfficeActivity`: TimeGenerated, Operation, UserId, MailboxOwnerUPN, ClientIP, ClientInfoString, ResultStatus, Parameters (string) | https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/officeactivity |
| Sentinel Entra ID connector: log types and tables, P1/P2 needed for sign-in logs | https://learn.microsoft.com/en-us/azure/sentinel/connect-azure-active-directory |

## Field shapes and values (Microsoft Graph resources that the log columns mirror)

| Item used | Source |
|---|---|
| `riskLevelDuringSignIn` / `riskLevelAggregated` values (none, low, medium, high, hidden) | https://learn.microsoft.com/en-us/graph/api/resources/signin?view=graph-rest-1.0 |
| `Status.additionalDetails`, `errorCode`, `failureReason` | https://learn.microsoft.com/en-us/graph/api/resources/signinstatus?view=graph-rest-1.0 |
| `LocationDetails.geoCoordinates` (signInLocation: city, state, countryOrRegion, geoCoordinates) | https://learn.microsoft.com/en-us/graph/api/resources/signinlocation?view=graph-rest-1.0 |
| `geoCoordinates.latitude` / `.longitude` | https://learn.microsoft.com/en-us/graph/api/resources/geocoordinates?view=graph-rest-1.0 |
| `riskEventType` enum (incl. `impossibleTravel`, `unlikelyTravel`), `riskLevel` values | https://learn.microsoft.com/en-us/graph/api/resources/riskdetection?view=graph-rest-1.0 |
| `TargetResources[]`: displayName, id, type, userPrincipalName, modifiedProperties | https://learn.microsoft.com/en-us/graph/api/resources/targetresource?view=graph-rest-1.0 |
| `InitiatedBy.user` / `InitiatedBy.app` | https://learn.microsoft.com/en-us/graph/api/resources/auditactivityinitiator?view=graph-rest-1.0 |
| `InitiatedBy.user.userPrincipalName`, `.ipAddress` | https://learn.microsoft.com/en-us/graph/api/resources/useridentity?view=graph-rest-1.0 |
| `InitiatedBy.app.displayName` | https://learn.microsoft.com/en-us/graph/api/resources/appidentity?view=graph-rest-1.0 |

## Detections, activity names, error codes

| Item used | Source |
|---|---|
| Risk detection names: unlikelyTravel, mcasImpossibleTravel, passwordSpray, attackerinTheMiddle, anomalousToken, suspiciousInboxForwarding, mcasSuspiciousInboxManipulationRules, userReportedSuspiciousActivity; "generic" for non-P2 | https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks |
| Entra audit activity names: Consent to application; Add delegated permission grant; Add app role assignment to service principal; Add service principal; Add service principal credentials; Update application - Certificates and secrets management; Add owner to application; Add member to role; Add eligible member to role; User/Admin registered security info; User deleted security info; Register device; Add device; Add/Update/Delete Conditional Access policy; Update named location; Set federation settings on domain; Set domain authentication; Add verified domain; Add user; Invite external user; Disable account; Update StsRefreshTokenValidFrom Timestamp; Reset password (by admin); Change user password; ConfirmAccountCompromised; Suspicious activity reported; Fraud reported - user is blocked for MFA; Fraud reported - no action taken | https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities |
| Error codes 50126, 500121, 53003, 50057; legacy client apps; "MFA Denied" fraud alerts; 30-day audit retention | https://learn.microsoft.com/en-us/entra/architecture/security-operations-user-accounts |
| 500121 = "Authentication failed during strong authentication request." | https://login.microsoftonline.com/error?code=500121 |
| MFA denial filter (`Status.additionalDetails` "MFA denied; user declined the authentication" / "fraud") | https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Microsoft%20Entra%20ID/Analytic%20Rules/MFARejectedbyUser.yaml |
| "Report suspicious activity" raises user risk to high | https://learn.microsoft.com/en-us/entra/identity/authentication/howto-mfa-mfasettings |
| Exchange audit operations New-InboxRule, Set-InboxRule, UpdateInboxRules; Audit (Standard) 180-day retention | https://learn.microsoft.com/en-us/purview/audit-log-activities |
| Inbox rule parameters ForwardTo, ForwardAsAttachmentTo, RedirectTo, DeleteMessage, SoftDeleteMessage, PermanentDelete, MoveToFolder, MarkAsRead | https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/new-inboxrule?view=exchange-ps |
| App consent investigation: IsAdminConsent, ConsentType AllPrincipals/Principal, high-risk delegated scopes, disable the app rather than delete it | https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-app-consent |

## KQL functions

| Item used | Source |
|---|---|
| `geo_distance_2points(p1_lon, p1_lat, p2_lon, p2_lat)` returns meters | https://learn.microsoft.com/en-us/kusto/query/geo-distance-2points-function |
| `prev()` needs a serialized row set (`sort by` serializes) | https://learn.microsoft.com/en-us/kusto/query/prev-function |
| Parser used for the static check: Kusto.Language (NuGet `Microsoft.Azure.Kusto.Language` 12.4.1) | https://github.com/microsoft/Kusto-Query-Language |

## Containment and eradication APIs

| Item used | Source |
|---|---|
| `POST /users/{id}/revokeSignInSessions`, `Revoke-MgUserSignInSession`, `User.RevokeSessions.All`, a few minutes' delay | https://learn.microsoft.com/en-us/graph/api/user-revokesigninsessions?view=graph-rest-1.0 |
| Disable the account and devices, hybrid `Disable-ADAccount`, reset the password twice, ~1 h access token lifetime, CAE | https://learn.microsoft.com/en-us/entra/identity/users/users-revoke-access |
| `PATCH /users/{id}` accountEnabled / passwordProfile, `forceChangePasswordNextSignIn`, permissions and least roles | https://learn.microsoft.com/en-us/graph/api/user-update?view=graph-rest-1.0 |
| `POST /identityProtection/riskyUsers/confirmCompromised`, `Confirm-MgRiskyUserCompromised`, `IdentityRiskyUser.ReadWrite.All`, Security Administrator | https://learn.microsoft.com/en-us/graph/api/riskyuser-confirmcompromised?view=graph-rest-1.0 |
| `DELETE /oAuth2PermissionGrants/{id}`, `Remove-MgOauth2PermissionGrant`, existing tokens stay valid | https://learn.microsoft.com/en-us/graph/api/oauth2permissiongrant-delete?view=graph-rest-1.0 |
| `GET /users/{id}/authentication/methods`, `Get-MgUserAuthenticationMethod`, `UserAuthenticationMethod.Read.All` | https://learn.microsoft.com/en-us/graph/api/authentication-list-methods?view=graph-rest-1.0 |
| CA block by location, break-glass exclusion, report-only first, applied after first-factor auth, Conditional Access Administrator | https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-block-by-location |
| `Get-InboxRule` / `Remove-InboxRule` | https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/remove-inboxrule?view=exchange-ps |

## Frameworks

| Item used | Source |
|---|---|
| NIST SP 800-61 Rev. 2: Preparation; Detection & Analysis; Containment, Eradication & Recovery; Post-Incident Activity (Figure 3-1) | https://csrc.nist.gov/pubs/sp/800/61/r2/final |
| NIST SP 800-61 Rev. 3 (April 2025): supersedes Rev. 2; Table 1 maps the Rev. 2 phases to CSF 2.0 Functions | https://csrc.nist.gov/pubs/sp/800/61/r3/final |

## MITRE ATT&CK (Enterprise)

| ID | Name | Source |
|---|---|---|
| T1078.004 | Valid Accounts: Cloud Accounts | https://attack.mitre.org/techniques/T1078/004/ |
| T1110.003 | Brute Force: Password Spraying | https://attack.mitre.org/techniques/T1110/003/ |
| T1621 | Multi-Factor Authentication Request Generation | https://attack.mitre.org/techniques/T1621/ |
| T1114.003 | Email Collection: Email Forwarding Rule | https://attack.mitre.org/techniques/T1114/003/ |
| T1564.008 | Hide Artifacts: Email Hiding Rules | https://attack.mitre.org/techniques/T1564/008/ |
| T1528 | Steal Application Access Token | https://attack.mitre.org/techniques/T1528/ |
| T1566.002 | Phishing: Spearphishing Link | https://attack.mitre.org/techniques/T1566/002/ |
| T1550.001 | Use Alternate Authentication Material: Application Access Token | https://attack.mitre.org/techniques/T1550/001/ |
| T1539 | Steal Web Session Cookie | https://attack.mitre.org/techniques/T1539/ |
| T1557 | Adversary-in-the-Middle | https://attack.mitre.org/techniques/T1557/ |
| T1098.001 | Account Manipulation: Additional Cloud Credentials | https://attack.mitre.org/techniques/T1098/001/ |
| T1098.003 | Account Manipulation: Additional Cloud Roles | https://attack.mitre.org/techniques/T1098/003/ |
| T1098.005 | Account Manipulation: Device Registration | https://attack.mitre.org/techniques/T1098/005/ |
| T1556.006 | Modify Authentication Process: Multi-Factor Authentication | https://attack.mitre.org/techniques/T1556/006/ |
