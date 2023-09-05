import { COSESign1, Label } from "@emurgo/cardano-message-signing-nodejs";
import {
  Address,
  BaseAddress,
  Ed25519KeyHash,
  Ed25519Signature,
  PublicKey,
  StakeCredential,
} from "@emurgo/cardano-serialization-lib-nodejs";

export const verify = async (
  address: string,
  signature: string,
  publicKey: string
) => {
  if (!signature) {
    console.error("Signature required");
    return null;
  }

  if (!signature || !signature.length) {
    console.error("Token malformed (empty signature)");
    return null;
  }

  const sbytes = Buffer.from(signature, "hex");
  const message = COSESign1.from_bytes(sbytes);

  const headermap = message.headers().protected().deserialized_headers();
  const lbl = Label.new_text("address");
  const cborHeader = headermap.header(lbl);

  if (!cborHeader) {
    throw new Error("Invalid header");
  }

  const cborHeaderBytes = cborHeader.as_bytes();

  if (!cborHeaderBytes) {
    throw new Error("Invalid header bytes");
  }

  const pubKey = PublicKey.from_bytes(Buffer.from(publicKey, "hex"));

  const coseSign = COSESign1.from_bytes(Buffer.from(signature, "hex"));
  const edsSignature = Ed25519Signature.from_bytes(coseSign.signature());
  const data = coseSign.signed_data().to_bytes();

  const verified = pubKey.verify(data, edsSignature);
  const coseAddress = Address.from_bytes(cborHeaderBytes);

  if (!verifyAddress(address, coseAddress, pubKey)) {
    throw new Error("Invalid address");
  }

  return { address: coseAddress.to_bech32(), success: verified };
};

const verifyAddress = (
  address: string,
  addressCose: Address,
  publicKeyCose: PublicKey
) => {
  // check if BaseAddress
  try {
    const baseAddress: BaseAddress | undefined =
      BaseAddress.from_address(addressCose);

    if (!baseAddress) {
      throw new Error("Failed to get base address from addressCose");
    }

    // reconstruct address
    const paymentKeyHash = publicKeyCose.hash();

    const stakeKeyHash: Ed25519KeyHash | undefined = baseAddress
      .stake_cred()
      .to_keyhash();

    if (!stakeKeyHash) {
      throw new Error("Failed to find stake key hash");
    }

    const reconstructedAddress = BaseAddress.new(
      1,
      StakeCredential.from_keyhash(paymentKeyHash),
      StakeCredential.from_keyhash(stakeKeyHash)
    );

    return reconstructedAddress.to_address().to_bech32() === address;
  } catch (error) {
    console.error("Caught error verifying address", error);
  }

  return null;
};
