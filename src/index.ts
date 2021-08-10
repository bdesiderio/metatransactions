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
    const provider = new providers.JsonRpcProvider("HTTP://127.0.0.1:8545");
    const ownerAddress = '0x06bB4674A4b08d07186b721378C7e241eD85443b';
    //const ownerPrivateKey = '0x0936af475d2701538aad321f87e0a51f2b297634653393e8cab7290a674009a5';
    const ownerPrivateKey = '0936af475d2701538aad321f87e0a51f2b297634653393e8cab7290a674009a5';
    const newOwnerAddress = '0x6d197071d41C77A2779B33304B8cC6Ea41f69918';
    const newOwnerPrivateKey = '5e697f9196588307b9e818fafca38c33f6592c005bfd190820b1d2cc2d608882';
    const registry = '0x4EA2D8B4c8B54989fa826bb401f2f01424ee6eA0';
    const wallet = new Wallet(ownerPrivateKey, provider);
    const uint8ArrayOwnerPrivateKey = Buffer.from('0936af475d2701538aad321f87e0a51f2b297634653393e8cab7290a674009a5', 'hex')

    
    const contract: Contract = ContractFactory.fromSolidity(DidRegistryContract)
        .attach(registry) 
        .connect(wallet);


   
        const nonce2 = await contract.nonce( ownerAddress );
		
        const sig2 = await signData(
			ownerAddress,
			ownerPrivateKey,
            Buffer.from( "changeOwner" ).toString( "hex" ) +
			stripHexPrefix( newOwnerAddress ),
			nonce2.toNumber(),
			registry
		);
		await contract.changeOwnerSigned(
			ownerAddress,
			sig2.v,
			sig2.r,
			sig2.s,
			newOwnerAddress,
			{
				gasLimit: 600000, gasPrice: 20000000000,
			}
		);

}



example2();