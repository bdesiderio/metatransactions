import { utils, Transaction, Signer, BigNumber, Wallet, providers, Signature } from "ethers";
import Web3 from "web3";
import DidRegistryContract from 'ethr-did-registry';
import { EthrDidController } from "ethr-did-resolver";
import { CallOverrides, Contract, ContractFactory } from '@ethersproject/contracts';
import { TransactionRequest } from "@ethersproject/abstract-provider";

import { keccak256, defaultAbiCoder, toUtf8Bytes, solidityPack, arrayify, splitSignature, joinSignature } from 'ethers/lib/utils'
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

    const nonce = await provider.getTransactionCount(identity);
    const registryNonce = await contract.nonce(identity);

    // const sig2 = await signData(
    //     identity,
    //     ownerPrivateKey,
    //     Buffer.from("changeOwner").toString("hex") +
    //     stripHexPrefix(newOwnerAddress),
    //     nonce2.toNumber(),
    //     registry
    // );

    // console.log(sig2);

    const dataToSign = "19007EEb5772eF87C40255a74C7cC05317C08eA64214000000000000000000000000000000000000000000000000000000000000000e06bB4674A4b08d07186b721378C7e241eD85443b6368616e67654f776e657206bB4674A4b08d07186b721378C7e241eD85443b";
    const hash = Buffer.from(ethutils.sha3(Buffer.from(dataToSign, "hex")));

    var transaction: TransactionRequest = {
        from: identity,
        gasLimit: 600000,
        gasPrice: 20000000000,
        nonce: nonce,
        data: hash,
        to: "0x7EEb5772eF87C40255a74C7cC05317C08eA64214",
    };

    const signature = await wallet.signTransaction(transaction);
    const sig2 = splitSignature(signature)

    await contract.changeOwnerSigned(
        identity,
        sig2.v,
        sig2.r,
        sig2.s,
        newOwnerAddress,
        {
            gasLimit: 600000, gasPrice: 20000000000,
        }
    );
}

const example3 = async () => {
    const provider = new providers.JsonRpcProvider("HTTP://127.0.0.1:7545");
    const identity = '0x4cf7169d86216E46308b0CEA79eb3Bc16e869bCD';
    const ownerAddress = '0x4cf7169d86216E46308b0CEA79eb3Bc16e869bCD';
    // const ownerPrivateKey = 'b7ecb1603741d86609d5075b7acae84ff94422e18c17f64e5a9a508ebe841aad'; //x3C58
    const ownerPrivateKey = 'f768e73830e4f8c8f121ec39316fc170dfe9b189ae0bf6ac0dba4acc97d97ade'; //0x06bB
    // const ownerPrivateKey = '5e697f9196588307b9e818fafca38c33f6592c005bfd190820b1d2cc2d608882';
    const newOwnerAddress = '0x4cf7169d86216E46308b0CEA79eb3Bc16e869bCD';
    const registry = '0x7EEb5772eF87C40255a74C7cC05317C08eA64214';
    const wallet = new Wallet(ownerPrivateKey, provider);

    const contract: Contract = ContractFactory.fromSolidity(DidRegistryContract)
        .attach(registry)
        .connect(wallet);

    const nonce = await provider.getTransactionCount(ownerAddress);
    const registryNonce = await contract.nonce(identity);

    let payloadHash = utils.solidityKeccak256(['bytes1', 'bytes1', 'address', 'uint256', 'address', 'string', 'address'],
        [
            "0x19",
            "0x00",
            registry,
            registryNonce.toNumber(),
            identity,
            'changeOwner',
            newOwnerAddress
        ]);

    const messageBytes = utils.arrayify(payloadHash);

    // let signature = await wallet.signMessage(messageBytes);
    const sig2 = ethutils.ecsign(messageBytes, Buffer.from(ownerPrivateKey, 'hex'));
    const signRSV = {
        r: `0x${sig2.r.toString("hex")}`,
        s: `0x${sig2.s.toString("hex")}`,
        v: sig2.v
    };



    //se hashea primero la función con los parámetros de entrada
    const buffer = Buffer.from("changeOwnerSigned(address,uint8,bytes32,bytes32,address)");

    //Se toman los primeros 4 bytes
    const fun = utils.keccak256(buffer).substr(0, 10).replace("0x", "");

    //Los numeros hay que pasarlos a Hexadecimal
    const hexaV = signRSV.v.toString(16);

    //A cada parámetro hay que hacerle un Padding de 32 bytes hacia la izquierda. Los parámetros deben ir en el orden en que los espera el SC
    const dataIdentity = pad32Bytes(identity.replace("0x", ""));
    const dataSigV = pad32Bytes(hexaV).replace("0x", "");
    const dataSigR = pad32Bytes(signRSV.r).replace("0x", "");
    const dataSigS = pad32Bytes(signRSV.s).replace("0x", "");
    const dataNewOwner = pad32Bytes(newOwnerAddress.replace("0x", ""));

    //Finalmente se concatenan todos los datos en un sólo string (no olvidar el "0x" +)
    const finalData = "0x" + fun + dataIdentity + dataSigV + dataSigR + dataSigS + dataNewOwner;

    var transaction: TransactionRequest = {
        from: ownerAddress,
        gasLimit: 600000,
        gasPrice: 20000000000,
        nonce: nonce,
        data: finalData,
        to: "0x7EEb5772eF87C40255a74C7cC05317C08eA64214",
    };

    await wallet.sendTransaction(transaction);
}

const pad32Bytes = (data: string) => {
    var s = String(data);
    while (s.length < (64 || 2)) { s = "0" + s; }
    return s;
}


const example4 = () => {
    //if (!this.wallet) throw new Error("Cannot sign content because wallet was not initialized with secrets.")
    const content = {
        data: {
            header1: {
                type: 'bytes1',
                value: "0x19"
            },
            header2: {
                type: 'bytes1',
                value: "0x00"
            },
            registry: {
                type: 'address',
                value: "0x7EEb5772eF87C40255a74C7cC05317C08eA64214"
            },
            registryNonce: {
                type: "uint256",
                value: "0x18",
            },
            identity: {
                type: "address",
                value: "0x4cf7169d86216E46308b0CEA79eb3Bc16e869bCD",
            },
            operation: {
                type: "string",
                value: "changeOwner",
            },
            newOwner: {
                type: "address",
                value: "0x4cf7169d86216E46308b0CEA79eb3Bc16e869bCD",
            }
        }
    };

    const firstArray = new Array<string>();
    const secondArray = new Array<string>();


    for (let i in content.data) {
        firstArray.push((<any>content).data[i].type);
        secondArray.push((<any>content).data[i].value);
    }

    let payloadHash = utils.solidityKeccak256(firstArray, secondArray);

    const messageBytes = utils.arrayify(payloadHash);

    const signature = (<any>ethutils).ecsign(messageBytes, Buffer.from(
        "f768e73830e4f8c8f121ec39316fc170dfe9b189ae0bf6ac0dba4acc97d97ade", 'hex'));

    const s = {
        r: `0x${signature.r.toString("hex")}`,
        s: `0x${signature.s.toString("hex")}`,
        v: signature.v,
        //signature: "s" //TODO Devolver la signature compuesta
    };

    const joinedSignature = joinSignature({
        r: s.r,
        s: s.s,
        v: s.v,
    });

    return {
        r: s.r,
        s: s.s,
        v: s.v,
        signature: joinedSignature
    };
}


// example2();
example4();