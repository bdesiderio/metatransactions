import { utils, Transaction, Signer, BigNumber, Wallet, providers, Signature } from "ethers";
import Web3 from "web3";
import DidRegistryContract from 'ethr-did-registry';
import { EthrDidController } from "ethr-did-resolver";
import { CallOverrides, Contract, ContractFactory } from '@ethersproject/contracts';
import { TransactionRequest } from "@ethersproject/abstract-provider";

import { keccak256, defaultAbiCoder, toUtf8Bytes, solidityPack } from 'ethers/lib/utils'
import { BigNumberish } from 'ethers'
//import { ecsign } from 'ethereumjs-util'
import { attributeToHex, signData, stringToBytes, stripHexPrefix, createKeyPair } from "./utils.js";

const ethutils = require("ethereumjs-util");

const b = async () => {
    const web3 = new Web3();
    // const signer = new Signer

    let fromAddr = "0xc225063366c3627B730f332c53E685b17fF7Ab9E"
    let toAddr = "0xA24dda953Bb3092b37f4692FB4a8c9AA8dCEf92f"
    let tokenValue = "1000000000000000000000"
    let calldata = ""

    const bb = BigNumber.from(12345);

    // get the function signature by hashing it and retrieving the first 4 bytes
    let fnSignature = web3.utils.keccak256("transferFrom(address,address,uint256)").substr(0, 10)
    // encode the function parameters and add them to the call data
    let fnParams = web3.eth.abi.encodeParameters(
        ["address", "address", "uint256"],
        [fromAddr, toAddr, tokenValue]
    );

    // const prov = new providers.JsonRpcSigner();
    // prov.get

    calldata = fnSignature + fnParams.substr(2)

    console.log(calldata);

    // let rawData = web3.eth.abi.encodeParameters(
    //     ['address', 'bytes'],
    //     ["0xA24dda953Bb3092b37f4692FB4a8c9AA8dCEf92f", data]
    // );

    const hash = await web3.eth.sign(calldata, "0xc225063366c3627B730f332c53E685b17fF7Ab9E");

}


const example2 = async () => {
    // const contract = new Contract("",)
    const provider = new providers.JsonRpcProvider("HTTP://127.0.0.1:7545");
    const identity = '0x06bB4674A4b08d07186b721378C7e241eD85443b';
    const ownerPrivateKey = '0936af475d2701538aad321f87e0a51f2b297634653393e8cab7290a674009a5';
    // const ownerPrivateKey = '5e697f9196588307b9e818fafca38c33f6592c005bfd190820b1d2cc2d608882';
    const newOwnerAddress = '0x06bB4674A4b08d07186b721378C7e241eD85443b';
    const registry = '0x7EEb5772eF87C40255a74C7cC05317C08eA64214';
    const wallet = new Wallet(ownerPrivateKey, provider);


    const contract: Contract = ContractFactory.fromSolidity(DidRegistryContract)
        .attach(registry)
        .connect(wallet);

    const nonce2 = await contract.nonce(identity);

    const sig2 = await signData(
        identity,
        ownerPrivateKey,
        Buffer.from("changeOwner").toString("hex") +
        stripHexPrefix(newOwnerAddress),
        nonce2.toNumber(),
        registry
    );

    console.log(sig2);
    // await contract.changeOwnerSigned(
    // 	identity,
    // 	sig2.v,
    // 	sig2.r,
    // 	sig2.s,
    // 	newOwnerAddress,
    // 	{
    // 		gasLimit: 600000, gasPrice: 20000000000,
    // 	}
    // );
}

const example3 = async () => {
    const provider = new providers.JsonRpcProvider("HTTP://127.0.0.1:7545");
    const identity = '0x06bB4674A4b08d07186b721378C7e241eD85443b';
    const ownerPrivateKey = '0936af475d2701538aad321f87e0a51f2b297634653393e8cab7290a674009a5';
    // const ownerPrivateKey = '5e697f9196588307b9e818fafca38c33f6592c005bfd190820b1d2cc2d608882';
    const newOwnerAddress = '0x06bB4674A4b08d07186b721378C7e241eD85443b';
    const registry = '0x7EEb5772eF87C40255a74C7cC05317C08eA64214';
    const wallet = new Wallet(ownerPrivateKey, provider);

    const contract: Contract = ContractFactory.fromSolidity(DidRegistryContract)
        .attach(registry)
        .connect(wallet);

    const nonce = await provider.getTransactionCount(identity);

    let dataToSign = "19007EEb5772eF87C40255a74C7cC05317C08eA64214000000000000000000000000000000000000000000000000000000000000000106bB4674A4b08d07186b721378C7e241eD85443b6368616e67654f776e657206bB4674A4b08d07186b721378C7e241eD85443b";
    let paylaodHash = Buffer.from(ethutils.sha3(Buffer.from(dataToSign, "hex")));
    // utils.keccak256(dataToSign);

    const messageBytes = utils.arrayify(paylaodHash);

    let signature = await wallet.signMessage(messageBytes);
    const sig2 = ethutils.ecsign(messageBytes, Buffer.from(ownerPrivateKey, 'hex'));
    const signRSV = {
		r: `0x${sig2.r.toString( "hex" )}`,
		s: `0x${sig2.s.toString( "hex" )}`,
		v: sig2.v
    };

    let sig = utils.splitSignature(signature);

    console.log("Public Key", wallet.publicKey);
    console.log("Address", wallet.address);

    // console.log("Recovered:", utils.verifyMessage(utils.arrayify(payloadHash), sig));
    // console.log("recoverAddress:", utils.recoverAddress(payloadHash, sig));
    // console.log("recoverPublicKey:", utils.recoverAddress(payloadHash, sig));

    // await contract.changeOwnerSigned(ownerAddress, sig.v, sig.r, sig.s, newOwnerAddress,
    //     { from: ownerAddress, gasLimit: 600000, gasPrice: 20000000000, nonce: nonce });
}



example3();
// example3();