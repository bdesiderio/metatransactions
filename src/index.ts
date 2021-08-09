import { utils, Transaction, Signer, BigNumber, Wallet, providers, Signature } from "ethers";
import Web3 from "web3";
import DidRegistryContract from 'ethr-did-registry';
import { EthrDidController } from "ethr-did-resolver";
import { CallOverrides, Contract, ContractFactory } from '@ethersproject/contracts';
import { TransactionRequest } from "@ethersproject/abstract-provider";

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
    const wallet = new Wallet("0xc3a877c3972beeca67d1257ff0e563507affe0f1dd267804258f6a4982d95ebc",
        provider);

    const contract: Contract = ContractFactory.fromSolidity(DidRegistryContract)
        .attach("0xc9d8473F6E44914EA105c7d53a02ddd1EECF7Dc5")
        .connect(wallet);


    let data = utils.solidityKeccak256(
        ['bytes1', 'bytes1', 'address', 'uint256', 'address', 'string', 'address'],
        [
            '0x19',
            '0x00',
            "0xc9d8473F6E44914EA105c7d53a02ddd1EECF7Dc5",
            0,
            '0xc225063366c3627B730f332c53E685b17fF7Ab9E',
            'changeOwner',
            '0xA24dda953Bb3092b37f4692FB4a8c9AA8dCEf92f'
        ]
    )


    let signedMessage = await wallet.signMessage(utils.arrayify(data));
    let sig = utils.splitSignature(signedMessage);

    const overrides = { gasLimit: 600000000, gasPrice: 20000000000 };
    const nonce = await provider.getTransactionCount('0xc225063366c3627B730f332c53E685b17fF7Ab9E');

    await contract.changeOwnerSigned("0xc225063366c3627B730f332c53E685b17fF7Ab9E", sig.v, sig.r, sig.s, "0xA24dda953Bb3092b37f4692FB4a8c9AA8dCEf92f",
        { from: "0xc225063366c3627B730f332c53E685b17fF7Ab9E", gasLimit: 600000, gasPrice: 20000000000, nonce: nonce });
}

example2();