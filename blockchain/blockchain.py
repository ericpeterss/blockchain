import time
import hashlib


class Transaction:
    def __init__(self, sender, receiver, amounts, fee, message):
        self.sender = sender
        self.receiver = receiver
        self.amounts = amounts
        self.fee = fee
        self.message = message


class Block:
    def __init__(self, previous_hash, difficulty, miner, miner_rewards):
        self.previous_hash = previous_hash
        self.hash = ""
        self.difficulty = difficulty
        self.nonce = 0
        self.timestamp = int(time.time())
        self.transactions = []
        self.miner = miner
        self.miner_rewards = miner_rewards


class Blockchain:
    def __init__(self):
        self.adjust_difficulty_blocks = 100  # adjust difficulty after how many blocks
        self.difficulty = 5
        self.block_time = 15
        self.miner_rewards = 50
        self.block_limitation = 10
        self.chain = []
        self.pending_transactions = []

    def transaction_to_string(self, transaction):
        transaction_dict = {
            "sender": str(transaction.sender),
            "receiver": str(transaction.receiver),
            "amounts": str(transaction.amounts),
            "fee": str(transaction.fee),
            "message": str(transaction.message),
        }
        return str(transaction_dict)

    def get_transactions_string(self, block):
        transaction_str = ""
        for transaction in block.transactions:
            transaction_str += self.transaction_to_string(transaction)
        return transaction_str

    def get_hash(self, block, nonce):
        s = hashlib.sha1()
        s.update((block.previous_hash + str(block.timestamp) + self.get_transactions_string(block) + str(nonce)).encode(
            "utf-8"))
        h = s.hexdigest()
        return h

    def add_transaction_to_block(self, block):
        # Get the transaction with highest fee by block_limitation
        # Sort by fee amount from highest to lowest
        self.pending_transactions.sort(key=lambda x: x.fee, reverse=True)
        # Exceed the limit, only accept the top XX transactions. Otherwise, accept all.
        if len(self.pending_transactions) > self.block_limitation:
            transaction_accepted = self.pending_transactions[:self.block_limitation]
            self.pending_transactions = self.pending_transactions[self.block_limitation:]
        else:
            transaction_accepted = self.pending_transactions
            self.pending_transactions = []
        block.transactions = transaction_accepted

    def create_genesis_block(self):
        print("Create genesis block...")
        new_block = Block("The first block from Eric!", self.difficulty, "Eric", self.miner_rewards)
        new_block.hash = self.get_hash(new_block, 0)
        self.chain.append(new_block)

    def mine_block(self, miner):
        start = time.process_time()

        last_block = self.chain[-1]
        new_block = Block(last_block.hash, self.difficulty, miner, self.miner_rewards)

        self.add_transaction_to_block(new_block)  # Wrap transactions to the current block
        new_block.previous_hash = last_block.hash  # It seems this line could be eliminated
        new_block.difficulty = self.difficulty  # It seems this line could be eliminated
        new_block.hash = self.get_hash(new_block, new_block.nonce)

        # Change the nonce until the hash could meet the difficulty
        while new_block.hash[:self.difficulty] != '0' * self.difficulty:
            new_block.nonce += 1
            new_block.hash = self.get_hash(new_block, new_block.nonce)

        time_consumed = round(time.process_time() - start, 5)
        print(f"Hash found: {new_block.hash} @ difficulty {self.difficulty}, time cost: {time_consumed}s")
        self.chain.append(new_block)


