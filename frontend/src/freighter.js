import {
  isConnected,
  setAllowed,
  getAddress,
  getNetworkDetails,
  getNetwork,
  signTransaction,
  signAuthEntry,
} from "@stellar/freighter-api";
import * as StellarSdk from "@stellar/stellar-sdk";
import { findNetworkByPassphrase, getActiveNetwork } from "./network";
import {
  buildAsset,
  parsePathAssets,
  buildSetOptionsBody,
  MAX_ASSET_CODE_LENGTH,
} from "./stellar";
import { parseHorizonError } from "./horizonErrorParse";
import { formatTrustlineLimit } from "./trustlineLimitFormat";
import { parseSimulationFees } from "./simulationFees";
import { getFeePerOperation } from "./feeSetting";
import {
  HORIZON_FAILURE_CODE,
  freighterCancelledError,
  horizonFailureError,
} from "./submitFailure";

export {
  FREIGHTER_CANCELLED_CODE,
  HORIZON_FAILURE_CODE,
  CANCELLED_RESULT,
  submitFailureResult,
} from "./submitFailure";

function getServer() {
  return new StellarSdk.Horizon.Server(getActiveNetwork().horizonUrl);
}

function currentPassphrase() {
  return getActiveNetwork().passphrase;
}

/** Selected fee per operation; falls back to the SDK default (100 stroops). */
function selectedFeePerOperation() {
  return getFeePerOperation() ?? StellarSdk.BASE_FEE;
}

const MAX_MEMO_TEXT_BYTES = 28;
const MAX_U64 = 18446744073709551615n;
export const TRANSACTION_FEE_STROOPS = StellarSdk.BASE_FEE;

/** Build a spec-driven client for the active network's contract calls. */
function kitewellClient(contractId) {
  return createKitewellClient({
    contractId,
    networkPassphrase: currentPassphrase(),
  });
}

/** Send prepared XDR to Freighter and return the signed transaction. */
function freighterSigner(publicKey) {
  return (unsignedXdr) => signWithFreighter(unsignedXdr, publicKey);
}

const WASM_MAGIC = [0x00, 0x61, 0x73, 0x6d]; // \0asm

/** Accept a File.arrayBuffer(), Uint8Array, or byte array, with a magic check. */
function normalizeWasmBytes(wasmBytes) {
  let bytes;
  if (wasmBytes instanceof Uint8Array) {
    bytes = wasmBytes;
  } else if (wasmBytes instanceof ArrayBuffer) {
    bytes = new Uint8Array(wasmBytes);
  } else if (Array.isArray(wasmBytes)) {
    bytes = Uint8Array.from(wasmBytes);
  } else {
    throw new Error("Choose the built kitewell.wasm file to deploy.");
  }

  if (bytes.length < 8 || !WASM_MAGIC.every((byte, i) => bytes[i] === byte)) {
    throw new Error("Not a Wasm binary — choose the built kitewell.wasm file.");
  }
  return bytes;
}

function newSalt() {
  const salt = new Uint8Array(32);
  globalThis.crypto.getRandomValues(salt);
  return salt;
}

function assertPublicKey(publicKey) {
  if (!StellarSdk.StrKey.isValidEd25519PublicKey(publicKey)) {
    throw new Error("Connect a valid Freighter address first.");
  }
}

/**
 * A create-contract tx has one host-function op; its result carries the new
 * contract ID as a 32-byte hash.
 */
function contractIdFromResult(resultXdr) {
  try {
    const result =
      typeof resultXdr === "string"
        ? StellarSdk.xdr.TransactionResult.fromXDR(resultXdr, "base64")
        : resultXdr;
    const createResult = result
      ?.result?.()
      ?.results?.()[0]
      ?.tr?.()
      ?.invokeHostFunctionResult?.();
    if (!createResult || createResult.switch().value !== 0) return null;
    return StellarSdk.Address.contract(createResult.success()).toString();
  } catch {
    return null;
  }
}

/** Prepare, sign with Freighter, submit, and poll until the tx is applied. */
async function prepareSignSubmit(transaction, publicKey, label) {
  const prepared = await sorobanRpc.prepareTransaction(transaction);
  const signedTx = await signWithFreighter(prepared.toXDR(), publicKey);
  const sendResult = await sorobanRpc.sendTransaction(signedTx);

  if (sendResult.status === "ERROR") {
    throw new Error(
      `${label} rejected by the network. Tx hash: ${sendResult.hash}`
    );
  }

  // RPC submission is asynchronous: poll getTransaction until applied.
  for (let attempt = 0; attempt < POLL_ATTEMPTS; attempt += 1) {
    const status = await sorobanRpc.getTransaction(sendResult.hash);
    if (status.status === "SUCCESS") {
      return { hash: sendResult.hash, returnValue: status.returnValue ?? null, status };
    }
    if (status.status === "FAILED") {
      throw new Error(`${label} failed on-chain. Tx hash: ${sendResult.hash}`);
    }
    await sleep(POLL_INTERVAL_MS);
  }

  // Still pending after the polling window; the tx may land shortly.
  return { hash: sendResult.hash, returnValue: null, status: null };
}

/**
 * Refuse to sign a contract invoke when Freighter is pointed at a different
 * network than the contract the backend reports. Previously this surfaced as
 * an opaque signing or submission failure after the wallet had already been
 * prompted.
 */
async function assertFreighterNetwork(expectedPassphrase) {
  const details = await getNetworkDetails();
  if (details.error) {
    throw new Error(
      details.error.message || "Could not read the network from Freighter."
    );
  }
  if (details.networkPassphrase !== expectedPassphrase) {
    throw new Error(
      `Freighter is on ${details.network}, but this contract is on a different network. ` +
        "Switch Freighter to the Lab network and try again."
    );
  }
}

/**
 * Read-only lookups against the Kitewell registry through the generated
 * client: lab_name(), builder_count(), get_builder(viewer), paused(), and
 * get_admin().
 *
 * @returns {{ labName: string, builderCount: number, builder: string|null,
 *   paused: boolean, admin: string|null }}
 */
export async function readKitewellState(contractId, viewerAddress) {
  return kitewellClient(contractId).readState(viewerAddress);
}

/**
 * Simulate the builder registration without signing or submitting it, so the
 * panel can show the return value and fee breakdown before the user signs.
 *
 * @returns {Promise<{
 *   error: string|null,
 *   inclusionFee: string|null,
 *   resourceFee: string|null,
 *   totalFee: string|null,
 *   returnValue: unknown,
 * }>} Fees in stroops.
 */
export async function simulateRegisterBuilder(publicKey, contractId, name) {
  const trimmed = (name || "").trim();
  if ([...trimmed].length > 64) {
    throw new Error("Builder name must be 64 characters or fewer.");
  }
  if (!StellarSdk.StrKey.isValidEd25519PublicKey(publicKey)) {
    throw new Error("Connect a valid Freighter address first.");
  }
  if (!StellarSdk.StrKey.isValidContract(contractId)) {
    throw new Error(
      "Contract ID must be a valid Soroban contract strkey (C…)."
    );
  }

  const contract = new StellarSdk.Contract(contractId);
  const sourceAccount = await sorobanRpc.getAccount(publicKey);
  const transaction = buildContractTx(
    contract,
    "register",
    [
      StellarSdk.nativeToScVal(publicKey, { type: "address" }),
      StellarSdk.nativeToScVal(trimmed, { type: "string" }),
    ],
    sourceAccount
  );

  // Simulation only: the user still has to press Sign to submit.
  const simulation = await sorobanRpc.simulateTransaction(transaction);
  const fees = parseSimulationFees(simulation, transaction.fee);
  const hasReturnValue =
    simulation?.result &&
    Object.prototype.hasOwnProperty.call(simulation.result, "retval");
  return {
    ...fees,
    error:
      fees.error || (hasReturnValue ? null : "Simulation returned no result."),
    returnValue:
      fees.error || !hasReturnValue
        ? null
        : StellarSdk.scValToNative(simulation.result.retval),
  };
}

/**
 * Check in a builder: builds + simulates a Soroban `register(caller, name)`
 * invoke, lets Freighter sign it, then submits via Soroban RPC and waits for
 * on-chain confirmation.
 *
 * @returns {{ hash: string, returnValue: unknown, confirmed: boolean }}
 */
export async function registerBuilderWithFreighter(
  publicKey,
  contractId,
  name,
  expectedPassphrase = currentPassphrase()
) {
  const trimmed = (name || "").trim();
  if (!trimmed) {
    throw new Error("Enter a builder name to register.");
  }
  if ([...trimmed].length > 64) {
    throw new Error("Builder name must be 64 characters or fewer.");
  }
  if (!StellarSdk.StrKey.isValidEd25519PublicKey(publicKey)) {
    throw new Error("Connect a valid Freighter address first.");
  }

  await assertFreighterNetwork(expectedPassphrase);

  return kitewellClient(contractId).register(
    publicKey,
    trimmed,
    freighterSigner(publicKey)
  );
}

/**
 * Pause or unpause registration. Only the contract admin's signature is
 * accepted; anyone else gets the contract's NotAdmin error in plain language
 * and the flag is left untouched.
 */
export async function setPausedWithFreighter(
  publicKey,
  contractId,
  paused,
  expectedPassphrase = currentPassphrase()
) {
  if (!StellarSdk.StrKey.isValidEd25519PublicKey(publicKey)) {
    throw new Error("Connect a valid Freighter address first.");
  }

  await assertFreighterNetwork(expectedPassphrase);

  return kitewellClient(contractId).setPaused(
    publicKey,
    Boolean(paused),
    freighterSigner(publicKey)
  );
}

/** Remove the connected builder's own check-in with their signature. */
export async function unregisterBuilderWithFreighter(
  publicKey,
  contractId,
  expectedPassphrase = currentPassphrase()
) {
  if (!StellarSdk.StrKey.isValidEd25519PublicKey(publicKey)) {
    throw new Error("Connect a valid Freighter address first.");
  }

  await assertFreighterNetwork(expectedPassphrase);

  return kitewellClient(contractId).unregister(
    publicKey,
    freighterSigner(publicKey)
  );
}

function createMemo(memoType, value) {
  if (!value) return null;

  if (memoType === "text") {
    if (new TextEncoder().encode(value).length > MAX_MEMO_TEXT_BYTES) {
      throw new Error("Text memos must be 28 UTF-8 bytes or fewer.");
    }
    return StellarSdk.Memo.text(value);
  }

  if (memoType === "id") {
    if (!/^\d{1,20}$/.test(value) || BigInt(value) > MAX_U64) {
      throw new Error("ID memos must be unsigned 64-bit integers.");
    }
    return StellarSdk.Memo.id(value);
  }

  if (memoType === "hash") {
    if (!/^[0-9a-fA-F]{64}$/.test(value)) {
      throw new Error("Hash memos must be exactly 64 hexadecimal characters.");
    }
    return StellarSdk.Memo.hash(value);
  }

  throw new Error(`Unsupported memo type: ${memoType}`);
}

export async function checkFreighterInstalled() {
  const result = await isConnected();
  return result.isConnected;
}

export async function connectFreighterWallet() {
  const installed = await isConnected();
  if (!installed.isConnected) {
    throw new Error(
      "Freighter is not installed. Get it from freighter.app, set Testnet, then refresh."
    );
  }

  const permission = await setAllowed();
  if (!permission.isAllowed) {
    throw new Error("Connection denied. Allow Kitewell in Freighter to continue.");
  }

  const addressResult = await getAddress();
  if (addressResult.error || !addressResult.address) {
    throw new Error(
      addressResult.error?.message || "Could not read the address from Freighter."
    );
  }

  return addressResult.address;
}

/**
 * Block signing when Freighter's network does not match the lab selection.
 * Checked on every sign attempt so switching either side clears the block
 * without a reload.
 */
export async function assertFreighterNetworkMatches() {
  const lab = getActiveNetwork();
  const freighter = await getNetwork();

  if (freighter?.error) {
    throw new Error(
      freighter.error.message || "Could not read the network from Freighter."
    );
  }

  const freighterPassphrase = freighter?.networkPassphrase;
  if (!freighterPassphrase || freighterPassphrase === lab.passphrase) {
    return;
  }

  const freighterLabel =
    findNetworkByPassphrase(freighterPassphrase)?.label ||
    freighter.network ||
    "unknown";

  throw new Error(
    `Freighter is on ${freighterLabel} but the lab is on ${lab.label}. Switch either side to match before signing.`
  );
}

/**
 * Sign a SEP-10 web-auth challenge in Freighter and return the signed XDR.
 *
 * This is the `sign(unsignedXdr)` callback `sep10WebAuth.js` asks for, so the
 * module never touches the extension and the key never leaves it either. The
 * challenge is an auth entry rather than a transaction to submit, which is why
 * it goes through `signAuthEntry` instead of {@link signWithFreighter}. It
 * clears the same network guard first, so a challenge is never signed on a
 * network the anchor did not issue it on.
 */
export async function signChallengeWithFreighter(unsignedXdr, publicKey) {
  await assertFreighterNetworkMatches();

  const signResult = await signAuthEntry(unsignedXdr, {
    networkPassphrase: currentPassphrase(),
    address: publicKey,
  });

  if (signResult.error || !signResult.signedAuthEntry) {
    throw new Error(
      signResult.error?.message || "Challenge signing was rejected in Freighter."
    );
  }

  return signResult.signedAuthEntry;
}

/** Ask Freighter to sign raw XDR and return the parsed signed transaction. */
async function signWithFreighter(unsignedXdr, publicKey) {
  await assertFreighterNetworkMatches();

  const passphrase = currentPassphrase();
  const signResult = await signTransaction(unsignedXdr, {
    networkPassphrase: passphrase,
    address: publicKey,
  });

  if (signResult.error || !signResult.signedTxXdr) {
    // Tag as cancelled so the failed-submit list does not treat this as Horizon.
    throw freighterCancelledError(
      signResult.error?.message || "Transaction signing was rejected in Freighter."
    );
  }

  return StellarSdk.TransactionBuilder.fromXDR(
    signResult.signedTxXdr,
    passphrase
  );
}

async function submitSignedTransaction(signedTx) {
  try {
    return await getServer().submitTransaction(signedTx);
  } catch (error) {
    const transactionFailure = getTransactionFailure(error);
    if (!transactionFailure) throw error;

    const failureError = horizonFailureError(
      "Transaction failed on the network."
    );
    failureError.transactionFailure = transactionFailure;
    throw failureError;
  }
}

async function signAndSubmit(transaction, publicKey) {
  const signedTx = await signWithFreighter(transaction.toXDR(), publicKey);
  return submitSignedTransaction(signedTx);
}

/**
 * Validate a Stellar amount string (positive, max 7 decimal places) without
 * going through floating point, so values like 0.0000001 stay intact.
 */
export function normalizeAmount(value, label = "Amount") {
  const text = String(value ?? "").trim();
  if (!/^\d+(\.\d{1,7})?$/.test(text)) {
    throw new Error(`${label} must be a positive number with up to 7 decimals.`);
  }

  const [whole, fraction = ""] = text.split(".");
  if (!/[1-9]/.test(whole) && !/[1-9]/.test(fraction)) {
    throw new Error(`${label} must be greater than zero.`);
  }

  return text;
}

/**
 * Resolve a UI payment asset descriptor into an SDK Asset.
 * `null` / `{ isNative: true }` is native XLM; a credit asset is
 * `{ isNative: false, code, issuer }`.
 */
export function resolvePaymentAsset(asset) {
  if (!asset || asset.isNative) return StellarSdk.Asset.native();

  const code = (asset.code || "").trim().toUpperCase();
  if (!code || code.length > 12) {
    throw new Error("Asset code must be 1–12 characters.");
  }
  if (!StellarSdk.StrKey.isValidEd25519PublicKey(asset.issuer)) {
    throw new Error("Asset issuer must be a valid Stellar public key (G…).");
  }

  return new StellarSdk.Asset(code, asset.issuer);
}

/**
 * Build an unsigned transaction envelope from an operation list.
 *
 * Nothing is signed or submitted: the returned base64 XDR can be shown to the
 * user, copied, or handed to another signer/decoder. Building with an empty
 * operation list is rejected, so there is never an empty envelope to copy.
 *
 * @param {string} publicKey source account (must be a valid Stellar key)
 * @param {StellarSdk.xdr.Operation[]} operations one or more operations
 * @param {{ memo?: StellarSdk.Memo|null, timeout?: number }} [options]
 * @returns {Promise<string>} base64-encoded transaction envelope XDR
 */
export async function buildUnsignedEnvelope(
  publicKey,
  operations,
  { memo = null, timeout = 180 } = {}
) {
  if (!StellarSdk.StrKey.isValidEd25519PublicKey(publicKey)) {
    throw new Error("Connect a valid Freighter address first.");
  }
  if (!Array.isArray(operations) || operations.length === 0) {
    throw new Error("Add at least one operation before building an envelope.");
  }

  // Load the account immediately before building so a stale sequence is refused.
  const sourceAccount = await getServer().loadAccount(publicKey);
  const txBuilder = new StellarSdk.TransactionBuilder(sourceAccount, {
    fee: selectedFeePerOperation(),
    networkPassphrase: currentPassphrase(),
  });

  operations.forEach((operation) => txBuilder.addOperation(operation));
  if (memo) txBuilder.addMemo(memo);

  return txBuilder.setTimeout(timeout).build().toXDR();
}

/**
 * Build the unsigned payment envelope without signing or submitting it.
 * `asset` accepts a UI descriptor (`{ isNative: true }` or
 * `{ isNative: false, code, issuer }`); omit it to send native XLM.
 *
 * @returns {Promise<string>} base64-encoded transaction envelope XDR
 */
export async function buildPaymentEnvelope(
  publicKey,
  destination,
  amount,
  asset = null,
  memoType = "text",
  memo = ""
) {
  const isAccountAddress =
    StellarSdk.StrKey.isValidEd25519PublicKey(destination) ||
    StellarSdk.StrKey.isValidMed25519PublicKey(destination);
  if (!isAccountAddress) {
    throw new Error(
      "Destination must be a valid Stellar public key (G…). A muxed address (M…) is also accepted."
    );
  }

  return buildUnsignedEnvelope(
    publicKey,
    [
      StellarSdk.Operation.payment({
        destination,
        asset: resolvePaymentAsset(asset),
        amount: amount.toString(),
      }),
    ],
    { memo: createMemo(memoType, memo) }
  );
}

/**
 * Sign an already-built unsigned envelope with Freighter and submit it.
 * Taking the XDR string keeps the signed payload identical to the one the user
 * previewed/copied.
 */
export async function submitEnvelopeWithFreighter(unsignedXdr, publicKey) {
  if (!unsignedXdr) {
    throw new Error("No unsigned envelope to sign.");
  }

  const signedTx = await signWithFreighter(unsignedXdr, publicKey);
  return submitSignedTransaction(signedTx);
}

/**
 * Build a payment op, sign it with Freighter, and submit it to Horizon.
 * `asset` accepts a UI descriptor (`{ isNative: true }` or
 * `{ isNative: false, code, issuer }`); omit it to send native XLM.
 * Optional `minTime` and `maxTime` are Unix timestamps (seconds) for transaction time bounds.
 * When both are provided, they replace the default timeout.
 */
export async function sendPaymentWithFreighter(
  publicKey,
  destination,
  amount,
  asset = null,
  memoType = "text",
  memo = "",
  minTime = null,
  maxTime = null
) {
  if (!StellarSdk.StrKey.isValidEd25519PublicKey(destination)) {
    if (typeof destination !== "string" || !destination.includes("*")) {
      throw new Error("Destination must be a valid Stellar public key (G…).");
    }
  }

  const resolvedDestination = await resolveFederationAddress(destination);
  if (!StellarSdk.StrKey.isValidEd25519PublicKey(resolvedDestination)) {
    throw new Error("Destination must be a valid Stellar public key (G…).");
  }

  // Validate time bounds if provided
  if (minTime !== null || maxTime !== null) {
    const min = minTime !== null ? Number(minTime) : 0;
    const max = maxTime !== null ? Number(maxTime) : 0;
    const now = Math.floor(Date.now() / 1000);

    if (minTime !== null && maxTime !== null && max <= min) {
      throw new Error("Maximum time must be after minimum time.");
    }
    if (maxTime !== null && max <= now) {
      throw new Error("Maximum time must be in the future.");
    }
  }

  const transactionMemo = createMemo(memoType, memo);
  const sourceAccount = await getServer().loadAccount(publicKey);
  const txBuilder = new StellarSdk.TransactionBuilder(sourceAccount, {
    fee: StellarSdk.BASE_FEE,
    networkPassphrase: currentPassphrase(),
  }).addOperation(
    StellarSdk.Operation.payment({
      destination: resolvedDestination,
      asset: resolvePaymentAsset(asset),
      amount: amount.toString(),
    })
  );

  if (transactionMemo) {
    txBuilder.addMemo(transactionMemo);
  }

  let transaction;
  if (minTime !== null || maxTime !== null) {
    const min = minTime !== null ? Number(minTime) : 0;
    const max = maxTime !== null ? Number(maxTime) : 0;
    transaction = txBuilder.setTimebounds(min, max).build();
  } else {
    transaction = txBuilder.setTimeout(180).build();
  }

  return signAndSubmit(transaction, publicKey);
}

/**
 * Build a path payment (strict send or strict receive), sign it with Freighter,
 * and submit it to Horizon Testnet.
 *
 * `sendAsset` / `destAsset` are UI descriptors ({ isNative } or
 * { isNative: false, code, issuer }). `path` is the optional comma-separated
 * intermediate hop list (e.g. "USDC:G…, XLM").
 *
 * Strict send fixes the amount sent (`amount`) and the minimum received
 * (`destMin`). Strict receive fixes the amount received (`amount`) and the
 * maximum sent (`sendMax`).
 */
export async function pathPaymentWithFreighter({
  publicKey,
  destination,
  mode = "strictSend",
  sendAsset,
  destAsset,
  amount,
  destMin,
  sendMax,
  path = "",
} = {}) {
  if (mode !== "strictSend" && mode !== "strictReceive") {
    throw new Error(`Unsupported path payment mode: ${mode}`);
  }
  if (!StellarSdk.StrKey.isValidEd25519PublicKey(destination)) {
    throw new Error("Destination must be a valid Stellar public key (G…).");
  }

  const isStrictReceive = mode === "strictReceive";
  const sourceAsset = buildAsset(sendAsset);
  const destinationAsset = buildAsset(destAsset);
  const intermediatePath = parsePathAssets(path);

  const amountValue = normalizeAmount(
    amount,
    isStrictReceive ? "Amount to receive" : "Amount to send"
  );
  const boundValue = normalizeAmount(
    isStrictReceive ? sendMax : destMin,
    isStrictReceive ? "Maximum to send" : "Minimum received"
  );

  const operation = isStrictReceive
    ? StellarSdk.Operation.pathPaymentStrictReceive({
        sendAsset: sourceAsset,
        sendMax: boundValue,
        destination: resolvedDestination,
        destAsset: destinationAsset,
        destAmount: amountValue,
        path: intermediatePath,
      })
    : StellarSdk.Operation.pathPaymentStrictSend({
        sendAsset: sourceAsset,
        sendAmount: amountValue,
        destination: resolvedDestination,
        destAsset: destinationAsset,
        destMin: boundValue,
        path: intermediatePath,
      });

  // Load the account immediately before building so a stale sequence is refused.
  const sourceAccount = await getServer().loadAccount(publicKey);
  const transaction = new StellarSdk.TransactionBuilder(sourceAccount, {
    fee: selectedFeePerOperation(),
    networkPassphrase: currentPassphrase(),
  })
    .addOperation(operation)
    .setTimeout(180)
    .build();

  return signAndSubmit(transaction, publicKey);
}

/** Reprice one open offer, keeping its offer id and remaining selling amount. */
export async function changeOfferPriceWithFreighter(publicKey, offer, newPrice) {
  if (!offer || !/^[1-9]\d*$/.test(String(offer.id))) {
    throw new Error("Select an open offer to reprice.");
  }
  const price = String(newPrice ?? "").trim();
  if (!/^\d+(\.\d+)?$/.test(price) || !/[1-9]/.test(price)) {
    throw new Error("New price must be greater than zero.");
  }

  // A partial fill may have changed the remaining amount since the list loaded.
  const currentOffer = await getServer().offers().offer(String(offer.id)).call();
  if (currentOffer.seller !== publicKey) {
    throw new Error("This offer is no longer open for the connected account.");
  }

  const selling = buildAsset({
    isNative: currentOffer.selling.asset_type === "native",
    code: currentOffer.selling.asset_code,
    issuer: currentOffer.selling.asset_issuer,
  });
  const buying = buildAsset({
    isNative: currentOffer.buying.asset_type === "native",
    code: currentOffer.buying.asset_code,
    issuer: currentOffer.buying.asset_issuer,
  });
  const amount = normalizeAmount(currentOffer.amount, "Remaining offer amount");
  const operation = StellarSdk.Operation.manageSellOffer({
    selling,
    buying,
    amount,
    price,
    offerId: String(offer.id),
  });

  const sourceAccount = await getServer().loadAccount(publicKey);
  const transaction = new StellarSdk.TransactionBuilder(sourceAccount, {
    fee: StellarSdk.BASE_FEE,
    networkPassphrase: currentPassphrase(),
  })
    .addOperation(operation)
    .setTimeout(180)
    .build();

  const result = await signAndSubmit(transaction, publicKey);
  return { ...result, oldPrice: currentOffer.price };
}

/**
 * Establish or raise a trustline for a credit asset on Testnet.
 * limit "0" removes the trustline (when balance is zero).
 */
export async function changeTrustWithFreighter(
  publicKey,
  assetCode,
  assetIssuer,
  limit = "1000000"
) {
  if (!assetCode || assetCode.length > 12) {
    throw new Error("Asset code must be 1–12 characters.");
  }
  if (!StellarSdk.StrKey.isValidEd25519PublicKey(assetIssuer)) {
    throw new Error("Issuer must be a valid Stellar public key (G…).");
  }

  const asset = new StellarSdk.Asset(assetCode.toUpperCase(), assetIssuer);
  // Load the account immediately before building so a stale sequence is refused.
  const sourceAccount = await getServer().loadAccount(publicKey);
  if (limit !== "0") {
    const baseReserve = await getLatestBaseReserve();
    const subentryCount = Number(sourceAccount.subentry_count);
    const nativeBalance = sourceAccount.balances?.find(
      (balance) => balance.asset_type === "native"
    )?.balance;
    if (!Number.isInteger(subentryCount) || nativeBalance == null) {
      throw new Error(
        "Could not verify the account balance and subentries; trustline signing is disabled."
      );
    }

    const hasTrustline = sourceAccount.balances.some(
      (balance) =>
        balance.asset_issuer === assetIssuer &&
        balance.asset_code === assetCode.toUpperCase()
    );
    const minimum = minimumBalanceInStroops(
      baseReserve,
      subentryCount + (hasTrustline ? 0 : 1)
    );
    if (
      !remainsAboveMinimum(
        nativeBalance,
        "0",
        StellarSdk.BASE_FEE,
        minimum
      )
    ) {
      const required = formatStroops(minimum + BigInt(StellarSdk.BASE_FEE));
      throw new Error(
        `Insufficient XLM for this trustline: the account needs ${required} XLM for its reserve and fee.`
      );
    }
  }

  const transaction = new StellarSdk.TransactionBuilder(sourceAccount, {
    fee: selectedFeePerOperation(),
    networkPassphrase: currentPassphrase(),
  })
    .addOperation(
      StellarSdk.Operation.changeTrust({
        asset,
        limit: limit.toString(),
      })
    )
    .setTimeout(180)
    .build();

  return signAndSubmit(transaction, publicKey);
}

/**
 * Resolve a federation address (e.g. "alice*stellar.org") into a Stellar
 * public key, using the configured resolver.
 *
 * @returns {string|null} Valid Stellar public key (G…) or null if unresolved.
 */
export async function resolveAddress(federationId) {
  if (!federationId) return null;
  const [name, domain] = federationId.split("*", 2);
  if (!name || !domain) return null;

  // Resolve via Soroban RPC, falling back to the legacy Horizon endpoint.
  try {
    const result = await sorobanRpc.resolveFederation(name, domain);
    if (result && result.address) return result.address;
  } catch (err) {
    console.warn("Soroban federation resolution failed:", err);
  }

  try {
    const response = await getServer().fetch(
      `/federation?type=name&id=${encodeURIComponent(federationId)}`,
      { cache: "no-store" }
    );
    const data = await response.json();
    if (data._embedded?.records?.[0]?.account_id) {
      return data._embedded.records[0].account_id;
    }
  } catch (err) {
    console.warn("Horizon federation resolution failed:", err);
  }

  return null;
}

/** Stellar's protocol limit for operations in one transaction. */
export const MAX_COMPOSED_OPERATIONS = 100;

const MAX_MANAGE_DATA_NAME_BYTES = 64;
const MAX_MANAGE_DATA_VALUE_BYTES = 64;

function assertComposedEntries(entries) {
  if (!Array.isArray(entries) || entries.length === 0) {
    throw new Error("Add at least one operation before signing.");
  }
  if (entries.length > MAX_COMPOSED_OPERATIONS) {
    throw new Error(
      `A transaction can contain at most ${MAX_COMPOSED_OPERATIONS} operations.`
    );
  }
}

/**
 * Turn one composer row into an SDK operation.
 *
 * Supported types: `payment`, `changeTrust`, and `manageData`. Validation
 * happens here so the composer can reject a bad row before the wallet opens.
 */
export function buildComposedOperation(entry = {}) {
  if (entry.type === "payment") {
    if (!StellarSdk.StrKey.isValidEd25519PublicKey(entry.destination)) {
      throw new Error("Destination must be a valid Stellar public key (G…).");
    }

    return StellarSdk.Operation.payment({
      destination: entry.destination,
      asset: resolvePaymentAsset(entry.asset),
      amount: normalizeAmount(entry.amount),
    });
  }

  if (entry.type === "changeTrust") {
    const code = String(entry.code ?? "").trim().toUpperCase();
    if (!code || code.length > 12) {
      throw new Error("Asset code must be 1–12 characters.");
    }
    if (!StellarSdk.StrKey.isValidEd25519PublicKey(entry.issuer)) {
      throw new Error("Issuer must be a valid Stellar public key (G…).");
    }

    return StellarSdk.Operation.changeTrust({
      asset: new StellarSdk.Asset(code, entry.issuer),
      limit: formatTrustlineLimit(entry.limit).formatted,
    });
  }

  if (entry.type === "manageData") {
    const name = String(entry.name ?? "").trim();
    if (!name) {
      throw new Error("Data entry name is required.");
    }
    if (new TextEncoder().encode(name).length > MAX_MANAGE_DATA_NAME_BYTES) {
      throw new Error("Data entry name must be 64 UTF-8 bytes or fewer.");
    }

    const value = String(entry.value ?? "");
    if (new TextEncoder().encode(value).length > MAX_MANAGE_DATA_VALUE_BYTES) {
      throw new Error("Data entry value must be 64 UTF-8 bytes or fewer.");
    }

    return StellarSdk.Operation.manageData({ name, value });
  }

  throw new Error(`Unsupported operation type: ${entry.type}`);
}

/**
 * Build one transaction containing every composer row, in list order.
 * The 100-operation protocol cap and per-row validation are enforced here.
 */
export function buildComposedTransaction(sourceAccount, entries) {
  assertComposedEntries(entries);

  const builder = new StellarSdk.TransactionBuilder(sourceAccount, {
    fee: StellarSdk.BASE_FEE,
    networkPassphrase: currentPassphrase(),
  });

  for (const entry of entries) {
    builder.addOperation(buildComposedOperation(entry));
  }

  return builder.setTimeout(180).build();
}

function horizonErrorBody(error) {
  const body = error?.response?.data ?? error?.response;
  if (body && typeof body === "object") return body;
  // signAndSubmit wraps a Horizon failure and keeps the raw error as `cause`.
  if (error?.cause) return horizonErrorBody(error.cause);
  return null;
}

/**
 * Horizon's zero-based index of the first failed operation in a submit error,
 * or null when the response does not name one.
 */
export function getFailedOperationIndex(error) {
  const body = horizonErrorBody(error);
  const codes = body?.extras?.result_codes?.operations;
  if (!Array.isArray(codes)) return null;

  const index = codes.findIndex((code) => code && code !== "op_success");
  return index === -1 ? null : index;
}

function withFailedOperationIndex(error) {
  const index = getFailedOperationIndex(error);
  if (index == null) return error;

  const body = horizonErrorBody(error);
  let reason = "transaction failed";
  try {
    reason = parseHorizonError(body).reason;
  } catch {
    /* keep the generic reason */
  }

  const wrapped = new Error(`Operation index ${index} failed: ${reason}`);
  wrapped.operationIndex = index;
  wrapped.cause = error;
  return wrapped;
}

/**
 * Sign the whole operation list once in Freighter and submit it to Horizon.
 * Empty lists and lists over 100 operations are rejected before Freighter is
 * opened. A failed submit carries `operationIndex` when Horizon names one.
 */
export async function submitComposedOperations(publicKey, entries) {
  assertComposedEntries(entries);

  // Validate every row before touching the wallet or the network.
  entries.forEach((entry) => buildComposedOperation(entry));

  if (!StellarSdk.StrKey.isValidEd25519PublicKey(publicKey)) {
    throw new Error("Connect a valid Freighter address first.");
  }

  const sourceAccount = await getServer().loadAccount(publicKey);
  const transaction = buildComposedTransaction(sourceAccount, entries);

  try {
    return await signAndSubmit(transaction, publicKey);
  } catch (error) {
    throw withFailedOperationIndex(error);
  }
}
