# EXAMPLE = [
    # {
    #     "flawed":"""
    #     """,
    #     "fixed":"""
    #     """
    # }
# ]

UNINITIALIZED_VARIABLES = [
    {
        "flawed":"""// Vulnerable
            contract Victim {
                address public owner;
                
                function getOwner() public view returns (address) {
                    return owner;
                }
            }

            // Attacker
            contract Hacker {
                function attack(Victim victim) public {
                    address owner = address(this);  // Uninitialized variable
                    victim.owner = owner;          // Set victim owner to this contract address
                }
            } 
        """,
        "fixed":"""contract VictimFixed {
            address public owner = address(0);    // Initialize owner to address(0)
            
            function getOwner() public view returns (address) {
                return owner;
            }
        }
        """
    },
    {
        "flawed":"""contract Victim {
            address public owner;
            mapping (address => uint) public balances;
            
            function getBalance(address addr) public view returns (uint) {
                return balances[addr];
            }
        }

        // Attacker
        contract Hacker {
            address victim;
            uint public hackerBalance; 
            
            constructor(address _victim) {
                victim = _victim;
                hackerBalance = 100;     // Initialize variable
            }
            
            function attack() public {
                Victim(victim).balances(address(this));   // Call getBalance through balances mapping 
            } 
            
            function getHackerBalance() public view returns (uint) {
                return hackerBalance;
            }
        }
        """,
        "fixed":"""contract VictimFixed {
            address public owner;
            mapping (address => uint) public balances; 
            
            constructor() {
                balances[owner] = 0;  // Initialize mapping
            }  
            
            function getBalance(address addr) public view returns (uint) {
                return balances[addr];
            }
        }
        """
    },
    {
        "flawed":"""contract Victim {
                address public owner;
                uint256 public count;
                
                function getCount() public view returns (uint256) {
                    return count; 
                }
            }

            // Attacker
            contract Hacker {
                uint256 public hackerCount;
                
                constructor() {
                    hackerCount = 100;
                }
                
                function attack(Victim victim) public {
                    victim.count;  // Call getCount() through count variable 
                }
            }

        """,
        "fixed":"""contract VictimFixed {
            address public owner;
            uint256 public count = 0;    // Initialize count
            
            function getCount() public view returns (uint256) {
                return count;
            }
        }
        """
    },
        {
        "flawed":"""contract Victim {
            address public owner;
            mapping(address => mapping(address => uint)) public balances;
            
            function getBalance(address to) public view returns (uint) {
                return balances[msg.sender][to];
            }
        }

        // Attacker
        contract Hacker {
            mapping(address => uint) public hackerBalances;
            
            function attack(Victim victim) public {
                victim.getBalance(address(this));
            }
            
            function setHackerBalance(uint amount) public {
                hackerBalances[msg.sender] = amount;
            }
        }
        """,
        "fixed":"""contract VictimFixed {
            address public owner;
            mapping(address => mapping(address => uint)) public balances; 
            
            constructor() {
                balances[owner][owner] = 0; // Initialize nested mapping
            }  
            
            function getBalance(address to) public view returns (uint) {
                return balances[msg.sender][to];
            }
        }
        """
    }
]

TX_ORIGIN_EXAMPLES = [
    {
        "flawed": """contract Victim {
            address owner = msg.sender;
            
            modifier onlyOwner() {
                require(tx.origin == owner); // tx.origin check is dangerous 
                _;
            }
            
            function changeOwner(address newOwner) public onlyOwner {
                owner = newOwner;
            }
        }

        // Attacker 
        contract Hacker {
            function attack(Victim victim) public {
                victim.changeOwner(address(this));
            }
            
            function() external {
                Victim(msg.sender).changeOwner(address(this));
            }
        }
        """,
        "fixed" : """contract VictimFixed {
            address owner = msg.sender;
            
            modifier onlyOwner() {
                require(msg.sender == owner); // Safer msg.sender check
                _; 
            }
            
            // ...
        }
        """
    },
    {
        "flawed":"""
        contract MyContract {

            address owner;

            function MyContract() public {
                owner = msg.sender;
            }

            function sendTo(address receiver, uint amount) public {
                require(tx.origin == owner);
                receiver.transfer(amount);
            }

        }
        """,
        "fixed":"""
            contract MyContract {

                address owner;

                function MyContract() public {
                    owner = msg.sender;
                }

                function sendTo(address receiver, uint amount) public {
                require(msg.sender == owner);
                receiver.transfer(amount);
                }

            }
        """
    },
    {
        "flawed":"""
        contract Victim {
            mapping(address => uint) public balances;
            address owner = msg.sender;
            
            function deposit() public payable {
                balances[msg.sender] += msg.value;
            }
            
            function withdraw(address to, uint amount) public {
                require(tx.origin == owner);  // Uses tx.origin for authorization
                require(balances[msg.sender] >= amount);
                balances[msg.sender] -= amount;
                to.transfer(amount);
            }
        }

        // Attacker contract
        contract Hacker {
            address victim;
            
            constructor(address _victim) {
                victim = _victim;
            }
            
            fallback() external payable {
                address(victim).delegatecall(
                    abi.encodeWithSignature("withdraw(address,uint256)", address(this), msg.value)
                );
            }
        }
        """,
        "fixed":"""
            contract VictimFixed {
            mapping(address => uint) public balances;
            address owner = msg.sender;
            
            function deposit() public payable {
                balances[msg.sender] += msg.value;
            }
            
            function withdraw(address to) public {
                require(msg.sender == owner); // Use msg.sender for authorization 
                require(balances[msg.sender] > 0);
                uint amount = balances[msg.sender];
                balances[msg.sender] = 0;
                to.transfer(amount);
            }
        }
        """
    },
    {
        "flawed":"""
        contract Victim {
            address public owner;
            uint public count;
            
            constructor() {
                owner = msg.sender; 
            }
            
            function changeOwner(address newOwner) public {
                require(tx.origin == owner); // Uses tx.origin for authorization
                owner = newOwner;
            }
            
            function increment() public {
                require(tx.origin == owner); // Uses tx.origin for authorization
                count++;
            }
        }

        // Attacker contract
        contract Hacker {
            address victim;
            
            constructor(address _victim) {
                victim = _victim;
            }
            
            function attack() public {
                address(victim).delegatecall(
                    abi.encodeWithSignature("changeOwner(address)", address(this))
                );
            }
            
            fallback() external {
                address(victim).delegatecall(
                    abi.encodeWithSignature("increment()")
                );
            }
        }
        """,
        "fixed":"""
        contract VictimFixed {
            address public owner;
            uint public count;
            
            constructor() {
                owner = msg.sender; 
            }
            
            function changeOwner(address newOwner) public {
                require(msg.sender == owner); // Use msg.sender for authorization
                owner = newOwner;
            }
            
            function increment() public {
                require(msg.sender == owner); // Use msg.sender for authorization
                count++; 
            }
        }
        """
    }
]

REENTRANCY_EXAMPLES = [
    {
        "flawed": """contract Fund {
            mapping(address => uint) public balances;
            
            function withdraw(uint amount) public {
                uint balance = balances[msg.sender];
                require(balance >= amount);
                balances[msg.sender] = balance - amount;
                msg.sender.transfer(amount); // Reentrancy could happen here
            }
            }""",
        "fixed" : """contract Fund {
            mapping(address => uint) public balances;
            bool private locked;
            
            function withdraw(uint amount) public {
                require(!locked); // Checks for reentrancy
                locked = true;
                uint balance = balances[msg.sender];
                require(balance >= amount);
                balances[msg.sender] = balance - amount;
                msg.sender.transfer(amount); 
                locked = false; 
            }
        }"""
    },
    {
        "flawed":"""contract Exchange {
            mapping(address => uint) public balances;
            mapping(address => bool) public hasWithdrawn;
            
            function deposit() public payable {
                balances[msg.sender] += msg.value;
            }
            
            function withdraw() public {
                require(hasWithdrawn[msg.sender] == false); 
                uint amount = balances[msg.sender];
                balances[msg.sender] = 0;
                msg.sender.transfer(amount);
                hasWithdrawn[msg.sender] = true;
            }
        }
        """,
        "fixed":"""
            contract Exchange {
            mapping(address => uint) public balances;
            mapping(address => bool) public hasWithdrawn;
            
            function deposit() public payable {
                balances[msg.sender] += msg.value;
            }

            function withdraw() public {
                require(hasWithdrawn[msg.sender] == false); 
                uint amount = balances[msg.sender];
                balances[msg.sender] = 0;
                hasWithdrawn[msg.sender] = true; 
                msg.sender.transfer(amount); 
            }
        }
        """
    }
]

OVERFLOW_UNDERFLOW_EXAMPLES = [
    {
        "flawed": """contract IntegerOverflowMinimal {
            uint public count = 1;

            function run(uint256 input) public {
                count -= input;
            }
        }
        """,
        "fixed" : """contract IntegerOverflowMinimal {
            uint public count = 1;

            function run(uint256 input) public {
                count = sub(count,input);
            }

            //from SafeMath
            function sub(uint256 a, uint256 b) internal pure returns (uint256) {
                require(b <= a);//SafeMath uses assert here
                return a - b;
            }
        }
        """
    },
    {
        "flawed":"""
        contract IntegerOverflowMul {
            uint public count = 2;

            function run(uint256 input) public {
                count *= input;
            }
        }
        """,
        "fixed":"""contract IntegerOverflowMul {
            uint public count = 2;

            function run(uint256 input) public {
                count = mul(count, input);
            }

            //from SafeMath
            function mul(uint256 a, uint256 b) internal pure returns (uint256) {
            // Gas optimization: this is cheaper than requiring 'a' not being zero, but the
            // benefit is lost if 'b' is also tested.
            // See: https://github.com/OpenZeppelin/openzeppelin-solidity/pull/522
            if (a == 0) {
                return 0;
            }

            uint256 c = a * b;
            require(c / a == b);

            return c;
            }
        }
        """
    },
    {
        "flawed":"""uint8 public count = 255;
        count++; // Overflow, count will be 0

        uint8 public count = 0;
        count--; // Underflow, count will be 255

        uint public totalSupply = 2**256 - 1; 
        totalSupply += 1; // Overflow, totalSupply will be 0
        """,
        "fixed":"""uint16 public count = 255;
        count++; // No overflow, count will be 256

        uint16 public count = 0;
        count--; // No underflow, count will be 65535

        uint256 public totalSupply = 2**256 - 1;
        totalSupply += 1; // No overflow 
        """
    },
    {
        "flawed":"""contract IntegerOverflowMultiTxOneFuncFeasible {
        uint256 private initialized = 0;
        uint256 public count = 1;

        function run(uint256 input) public {
            if (initialized == 0) {
                initialized = 1;
                return;
            }

            count -= input;
        }
    }
        """,
        "fixed":"""contract IntegerOverflowMultiTxOneFuncFeasible {

            uint256 private initialized = 0;
            uint256 public count = 1;

            function run(uint256 input) public {
                if (initialized == 0) {
                    initialized = 1;
                    return;
                }

                count = sub(count, input);
            }

            //from SafeMath
            function sub(uint256 a, uint256 b) internal pure returns (uint256) {
                require(b <= a);//SafeMath uses assert here
                return a - b;
            }
        }
        """
    }
]

GAS_EXCEEDED_EXAMPLES = [
    {
        "flawed": """contract GasLimit {
            uint256 public totalSupply = 2**256 - 1;
            
            function mint(address to, uint256 amount) public {
                totalSupply += amount;  // Uses gas for incrementing totalSupply
                balances[to] += amount; // Uses gas for incrementing balances
            }
        }
        """,
        "fixed" : """
        contract GasLimit {
            uint256 public totalSupply = 10**6;  // 1 million 
            
            function mint(address to, uint256 amount) public {
                totalSupply += amount;  
                balances[to] += amount;
            }
        }
        """
    },
    {
        "flawed": """contract Overflow {
            uint256[] public array;
            
            function push(uint256 elem) public {
                array.push(elem);  // Uses gas for expanding array and adding elem 
            }
        }
        """,
        "fixed" : """
        contract Overflow {
            uint256[] public array;
            uint maxSize = 1000;
            
            function push(uint256 elem) public {
                require(array.length < maxSize); // Check size limit
                array.push(elem);  
            }
        }
        """
    },
    {
        "flawed": """contract GasAttack {
            uint256 public totalSupply = 2**256 - 1;
            mapping(address => uint256) public balances;
            
            function mint(address to, uint256 amount) public {
                totalSupply += amount;        // Consumes gas
                balances[to] += amount;       // Consumes gas
            }
            
            function approve(address spender) public {
                allowed[msg.sender][spender] = totalSupply;  // Consumes huge gas
            }
        }
        """,
        "fixed" : """contract GasAttack {
            // ... 
            
            function approve(address spender) public {
                require(spender != msg.sender); 
                require(balances[msg.sender] > 0);
                allowed[msg.sender][spender] = balances[msg.sender];  
            }
        }
        """
    },
    {
        "flawed": """contract Registry {
            mapping(address => bool) public registeredAddresses;
            
            function register(address addr) public {
                require(!registeredAddresses[addr]);
                registeredAddresses[addr] = true; 
            }
            
            function unregister(address addr) public {
                require(registeredAddresses[addr]); 
                registeredAddresses[addr] = false;
            }
        }

        // Attacker contract
        contract GasAttacker {
            Registry public registry;
            
            constructor(Registry _registry) {
                registry = _registry;
            }
            
            function attack() public {
                for (uint i = 0; i < 2**256; i++) {
                    registry.unregister(address(i));  // Consumes all gas! 
                }
            }
        } 
        """,
        "fixed" : """contract Registry {
            mapping(address => bool) public registeredAddresses;
            uint maxSize = 2**10;  // Limit to 1024 addresses
            
            function register(address addr) public {
                require(registeredAddresses.length < maxSize);
                // ...
            }  
        }
        """
    }
]