import json
from bitcoinutils.transactions import TxInput

import init
import txs
from helper import hash256
from identity import Id

init.init_network()

FUTURE_SETUP_TIMELOCK = 1893456000  # 2030-01-01 00:00:00 UTC
REL_TIMELOCK = 2000
DISPUTE_TX_TIMELOCK = FUTURE_SETUP_TIMELOCK + 86400  # safely > T + T_rel
FUNDING_TX_ID = "da09f9ac4c16a0f988350bca3243c9e3b6b7f6b8c471db7c49c50de2cb2b3eeb"


def to_le_hex_u32(n: int) -> str:
    return n.to_bytes(4, byteorder="little", signed=False).hex()


def main():
    id_P = Id("d44348ff037a7f65bcf9b7c86181828f5e05dbfe6cf2efe9af6362c8d53a00b0")
    id_V = Id("b45349ff037a7f65bcf9b7c86181828f5e05dbfe6cf2efe9af6362c8d53a00b0")

    rev_secret_p_text = "Hey! This is P, and this is my revocation secret"
    rev_secret_v_text = "Hey! This is V, and this is my revocation secret"
    secret_rev_P = hash256(rev_secret_p_text.encode("utf-8").hex())
    secret_rev_V = hash256(rev_secret_v_text.encode("utf-8").hex())

    tx_lock_hex = to_le_hex_u32(DISPUTE_TX_TIMELOCK)
    tx_input = TxInput(FUNDING_TX_ID, 0)

    ct_P_locked = txs.get_ALBA_ct(
        tx_input,
        id_P,
        id_V,
        secret_rev_P,
        secret_rev_V,
        9000,
        9000,
        420,
        l=True,
        bothsigs=False,
        timelock=0x2,
        locked=True,
        tx_locktime_hex=tx_lock_hex,
    )

    ct_P_unlocked = txs.get_ALBA_ct(
        TxInput(FUNDING_TX_ID, 0),
        id_P,
        id_V,
        secret_rev_P,
        secret_rev_V,
        9000,
        9000,
        420,
        l=True,
        bothsigs=False,
        timelock=0x2,
        locked=False,
    )

    ct_V_unlocked = txs.get_standard_ct(
        TxInput(FUNDING_TX_ID, 0),
        id_P,
        id_V,
        secret_rev_V,
        9000,
        9000,
        420,
        l=False,
        bothsigs=False,
        timelock=0x2,
        locked=False,
    )

    out = {
        "futureSetupTimelock": FUTURE_SETUP_TIMELOCK,
        "relTimelock": REL_TIMELOCK,
        "disputeTxTimelock": DISPUTE_TX_TIMELOCK,
        "disputeTxTimelockLE": tx_lock_hex,
        "fundingTxId": "0x" + FUNDING_TX_ID,
        "CT_P_withVsig_Locked_Future": "0x" + ct_P_locked.serialize(),
        "CT_P_withVsig_Unlocked_Future": "0x" + ct_P_unlocked.serialize(),
        "CT_V_withPsig_Unlocked_Future": "0x" + ct_V_unlocked.serialize(),
        "revSecretP": rev_secret_p_text,
    }

    with open("data/sepoliaDisputeVectors.json", "w", encoding="utf-8") as f:
        json.dump(out, f, indent=4)

    print("Wrote data/sepoliaDisputeVectors.json")
    print("dispute tx locktime:", DISPUTE_TX_TIMELOCK, tx_lock_hex)


if __name__ == "__main__":
    main()
