import time, requests
from loguru import logger
from web3 import Web3
from termcolor import cprint
import random
from tqdm import tqdm

OUTFILE = ''
with open(f"{OUTFILE}wallets.txt", "r") as f:
    WALLETS = [row.strip() for row in f]

RPC         = 'https://rpc.ankr.com/arbitrum'
SLEEP_FROM  = 15
SLEEP_TO    = 30
RANDOM_WALLETS = True

ETH_PRICE = 1800

MAX_GAS = 2 # в баксах. если газ больше этого, будет спать 30с и пробовать снова

def sleeping(from_sleep, to_sleep):
    x = random.randint(from_sleep, to_sleep)
    for i in tqdm(range(x), desc='sleep ', bar_format='{desc}: {n_fmt}/{total_fmt}'):
        time.sleep(1)

# ============ web3_helpers ============

def intToDecimal(qty, decimal):
    return int(qty * int("".join(["1"] + ["0"]*decimal)))

def decimalToInt(qty, decimal):
    return qty/ int("".join((["1"]+ ["0"]*decimal)))

def sign_tx(web3, contract_txn, privatekey):

    signed_tx = web3.eth.account.sign_transaction(contract_txn, privatekey)
    raw_tx_hash = web3.eth.send_raw_transaction(signed_tx.rawTransaction)
    tx_hash = web3.to_hex(raw_tx_hash)
    
    return tx_hash

def check_status_tx(chain, tx_hash):

    logger.info(f'{chain} : checking tx_status : {tx_hash}')

    while True:
        try:
            rpc_chain   = RPC
            web3        = Web3(Web3.HTTPProvider(rpc_chain))
            status_     = web3.eth.get_transaction_receipt(tx_hash)
            status      = status_["status"]
            if status in [0, 1]:
                return status
            time.sleep(1)
        except Exception as error:
            # logger.info(f'error, try again : {error}')
            time.sleep(1)

def add_gas_limit(web3, contract_txn):

    try:
        pluser = [1.3, 1.7]
        gasLimit = web3.eth.estimate_gas(contract_txn)
        contract_txn['gas'] = int(gasLimit * random.uniform(pluser[0], pluser[1]))
        # logger.info(f"gasLimit : {contract_txn['gas']}")
    except Exception as error: 
        contract_txn['gas'] = random.randint(2000000, 3000000)
        logger.info(f"estimate_gas error : {error}. random gasLimit : {contract_txn['gas']}")

    # contract_txn['value'] = value
    return contract_txn

def add_gas_price(web3, contract_txn):

    try:
        gas_price = web3.eth.gas_price
        contract_txn['gasPrice'] = int(gas_price * random.uniform(1.2, 1.3))
    except Exception as error: 
        logger.error(error)

    return contract_txn

def check_data(wallet):

    headers = {
        'authority': 'bruhcoin.co',
        'accept': 'application/json, text/plain, */*',
        'accept-language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7',
        # 'content-length': '0',
        'origin': 'https://bruhcoin.co',
        'referer': 'https://bruhcoin.co/?ref=0xd066f1b6ce4ead45eb38facaf626e76a329804b9',
        'sec-ch-ua': '"Chromium";v="112", "Google Chrome";v="112", "Not:A-Brand";v="99"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"macOS"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
        'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36',
    }

    params = {
        'userAddress': wallet,
    }

    response = requests.post('https://bruhcoin.co/api/sinature', params=params, headers=headers)
    signature = response.json()["signature"]
    nonce = response.json()["nonce"]

    return signature, nonce

def claimer(privatekey):

    ABI = '[{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"user","type":"address"},{"indexed":false,"internalType":"uint128","name":"nonce","type":"uint128"},{"indexed":false,"internalType":"uint256","name":"amount","type":"uint256"},{"indexed":false,"internalType":"address","name":"referrer","type":"address"},{"indexed":false,"internalType":"uint256","name":"timestamp","type":"uint256"}],"name":"Claim","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"previousOwner","type":"address"},{"indexed":true,"internalType":"address","name":"newOwner","type":"address"}],"name":"OwnershipTransferred","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"address","name":"token","type":"address"},{"indexed":false,"internalType":"uint256","name":"startTime","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"endTime","type":"uint256"}],"name":"Start","type":"event"},{"inputs":[],"name":"INIT_CLAIM","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"MAX_ADDRESSES","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"MAX_REFER_TOKEN","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"MAX_TOKEN","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"","type":"address"}],"name":"_claimedUser","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"","type":"uint256"}],"name":"_usedNonce","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"canClaimAmount","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint128","name":"nonce","type":"uint128"},{"internalType":"bytes","name":"signature","type":"bytes"},{"internalType":"address","name":"referrer","type":"address"}],"name":"claim","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"claimedCount","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"claimedPercentage","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"claimedSupply","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"endTime","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"","type":"address"}],"name":"inviteRewards","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"","type":"address"}],"name":"inviteUsers","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"isStarted","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"owner","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"referReward","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"renounceOwnership","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"val","type":"address"}],"name":"setSigner","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"signer","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"_tokenAddress","type":"address"}],"name":"start","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"token","outputs":[{"internalType":"contract IERC20","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"newOwner","type":"address"}],"name":"transferOwnership","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"_token","type":"address"},{"internalType":"uint256","name":"_amount","type":"uint256"}],"name":"withdraw","outputs":[],"stateMutability":"nonpayable","type":"function"}]'

    try:

        from_chain = 'arbitrum'

        web3        = Web3(Web3.HTTPProvider(RPC))
        account     = web3.eth.account.from_key(privatekey)
        wallet      = account.address

        contract = web3.eth.contract(address=Web3.to_checksum_address('0x0857832548ab9dd3724943305b1ca5d230341b90'), abi=ABI)

        signature, claim_nonce = check_data(wallet)
        
        referrer = '0x77cE261C6AeE4FB481d393899F9aE12F15D82DCA' 

        contract_txn = contract.functions.claim(
            int(claim_nonce),
            bytes.fromhex(signature[2:]),
            referrer
            ).build_transaction(
            {
                "from": wallet,
                "nonce": web3.eth.get_transaction_count(wallet),
                'gasPrice': 0,
                'gas': 0,
                "value": 0
            }
        )

        contract_txn = add_gas_price(web3, contract_txn)
        contract_txn = add_gas_limit(web3, contract_txn)

        gas_gas = int(contract_txn['gas'] * contract_txn['gasPrice'])
        gas_value = decimalToInt(gas_gas, 18) * ETH_PRICE

        if gas_value < MAX_GAS:
        
            tx_hash = sign_tx(web3, contract_txn, privatekey)
            tx_link = f'https://arbiscan.io/tx/{tx_hash}'

            status = check_status_tx(from_chain, tx_hash)
            if status == 1:
                logger.success(tx_link)

            else:
                logger.info(f'tx is failed, try again in 10 sec | {tx_link}')
        
        else:
            logger.info(f'газ ебанутый : {gas_value} $ , спим и пробуем снова')
            sleeping(30,30)
            claimer(privatekey)


    except Exception as error:
        logger.error(error)



if __name__ == "__main__":

    if RANDOM_WALLETS == True:
        random.shuffle(WALLETS)

    zero = 0
    for wallet in WALLETS:
        zero += 1

        cprint(f'\n{zero}/{len(WALLETS)} : {wallet}', 'white')

        claimer(wallet)

        sleeping(SLEEP_FROM, SLEEP_TO)




