# Summary of KE Failure Retry Mechanism for IKE_SA_INIT

## Overview

An application-layer retry mechanism is implemented to allow the initiator to resend IKE_SA_INIT when it receives a response but fails to process the KE public key. The number of retries is configurable, with a default of 1.

## Modified Files

### 1. conf/options/charon.opt

**New configuration option:**

```
charon.max_ike_init_retries = 1
	Maximum number of times to retry IKE_SA_INIT when the initiator receives
	an IKE_SA_INIT response but fails to process it (e.g. key exchange failure).
	0 to disable retries.
```

- **Location**: between `charon.retry_initiate_interval` and `charon.reuse_ikesa`
- **Default**: 1
- **Purpose**: control retry attempts on KE failure
- **Examples**:
  - `1`: retry once (2 total attempts)
  - `2`: retry twice (3 total attempts)
  - `0`: disable retry, destroy IKE_SA on failure

### 2. src/libcharon/sa/ikev2/tasks/ike_init.c

#### a. New struct field

```c
/**
 * Retries due to key exchange public key application failure
 */
u_int ke_failed_retries;
```

- Tracks retries caused by KE public key processing failures. 
- Distinct from existing `retry` (used for INVALID_KE_PAYLOAD and COOKIE).

#### b. Modified ke_failed handling in process_i

**Original**:
```c
if (this->ke_failed)
{
    DBG1(DBG_IKE, "applying key exchange public value failed");
    return FAILED;
}
```

**New**:
```c
if (this->ke_failed)
{
    uint32_t max_retries;

    max_retries = lib->settings->get_int(lib->settings,
                        "%s.max_ike_init_retries", 1, lib->ns);

    if (max_retries > 0 && this->ke_failed_retries < max_retries)
    {
        DBG1(DBG_IKE, "applying key exchange public value failed, "
             "retrying IKE_SA_INIT (attempt %d/%d)",
             this->ke_failed_retries + 1, max_retries);
        this->ike_sa->reset(this->ike_sa, FALSE);
        this->ke_failed_retries++;
        return NEED_MORE;
    }
    DBG1(DBG_IKE, "applying key exchange public value failed");
    return FAILED;
}
```

## Workflow

```
1. Initiator sends IKE_SA_INIT
   ↓
2. Responder replies
   ↓
3. ike_init.process_i() processes response
   ↓
4. KE processing fails (ke_failed = TRUE)
   ↓
5. Check retry count:
   ├─ If below limit:
   │  ├─ call ike_sa->reset(false)
   │  ├─ increment ke_failed_retries counter
   │  ├─ return NEED_MORE
   │  ├─ task_manager detects reset flag
   │  ├─ calls initiate() to reactivate task
   │  └─ regenerate and send fresh IKE_SA_INIT
   │
   └─ Otherwise:
      ├─ return FAILED
      ├─ destroy IKE_SA
      └─ connection fails
```

## Example Logs

### Retry:
```
00[IKE]  charon[1234]: applying key exchange public value failed, retrying IKE_SA_INIT (attempt 1/1)
00[IKE]  charon[1234]: initiating IKE_SA net[1] to <PEER_ADDRESS>
```

### Over limit:

```
00[IKE]  charon[1234]: applying key exchange public value failed
00[IKE]  charon[1234]: charon[1234]: IKE_SA destroyed
```

## Configuration Example

### strongswan.conf
```ini
charon {
    # banning retry
    max_ike_init_retries = 0
    
    # default: retry once
    max_ike_init_retries = 1
    
    # allowing retry twice (3 total attempts)
    max_ike_init_retries = 2
}
```

## Test Scenarios

1. **Normal**: KE succeeds → continue IKE_AUTH
2. **Single retry**: 
	- 1st attempt: KE fails
	- trigger reset() and retry
	- 2nd attempt: KE succeeds → continue IKE_AUTH
3. **Multiple failures**: 
	- retry times exceed `max_ike_init_retries`
	- return FAILED
	- destroy SA

## Security Considerations

- Prevent DoS via retry limit
- RFC 7296 compliant (application-layer retry)
- State consistency ensured via reset()

## Compatibility

- Backward compatible (default = 1)
- Can disable (0)

## Comparison with Other Mechanisms

| Mechanism | Location | Trigger Condition | Behavior  |
| ----- | ----- | ----- | ----- |
| **INVALID_KE_PAYLOAD**   | ike_init.c | Responder rejects the KE method | Retry directly at the protocol layer, return `NEED_MORE` |
| **COOKIE**  | ike_init.c | Responder sends a COOKIE                    | Retry directly at the protocol layer, return `NEED_MORE` |
| **KE Failure Retry** | ike_init.c | KE public key decryption/verification fails | Retry at the application layer via `reset/initiate`|
| **retry_initiate_interval** | ike_sa.c   | Connection initialization fails             | Timer triggers a new initiation  |
