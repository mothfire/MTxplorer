contract Suicide {
    address public owner = msg.sender;
    uint public a;
    modifier onlyOwner{
        require(msg.sender == owner);
        _;
    }
    function setOwner() public{
        owner = msg.sender;
    }
    function kill(uint addr) public onlyOwner{
        a = addr;
    }
}
