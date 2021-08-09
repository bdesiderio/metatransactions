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
    const ownerAddress = '0x06bB4674A4b08d07186b721378C7e241eD85443b';
    const ownerPrivateKey = '0x0936af475d2701538aad321f87e0a51f2b297634653393e8cab7290a674009a5';
    const newOwnerAddress = '0x6d197071d41C77A2779B33304B8cC6Ea41f69918';
    const registry = '0x120546dDE845DCAb38AfF0c3062D5F970cFC4e1B';
    const wallet = new Wallet(ownerPrivateKey, provider);

    const contract: Contract = ContractFactory.fromSolidity(DidRegistryContract)
        .attach(registry) 
        .connect(wallet);


    let data =  utils.solidityKeccak256(
        ['bytes1', 'bytes1', 'address', 'uint256', 'address', 'string', 'address'],
        [
            '0x19',
            '0x00',
            registry,
            0,
            ownerAddress,
            'changeOwner',
            newOwnerAddress
        ]
    )

    /*var hash = "0x" + web3.utils.soliditySha3(
        ['bytes1', 'bytes1', 'address', 'uint256', 'address', 'string', 'address'],
        [
            '0x19',
            '0x00',
            registry,
            0,
            ownerAddress,
            'changeOwner',
            newOwnerAddress
        ]
      ).toString("hex");*/

    let signedMessage = await wallet.signMessage(utils.arrayify(data));
    let sig = utils.splitSignature(signedMessage);

    const overrides = { gasLimit: 600000000, gasPrice: 20000000000 };
    const nonce = await provider.getTransactionCount(ownerAddress);

    await contract.changeOwnerSigned(ownerAddress, sig.v, sig.r, sig.s, newOwnerAddress,
        { from: ownerAddress, gasLimit: 600000, gasPrice: 20000000000, nonce: nonce });
}

example2();