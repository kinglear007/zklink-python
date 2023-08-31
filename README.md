# zkLink Python SDK

### ZK signer lib (Dependence)


* Install Rust Compiler and Linker 
    ```
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    sudo apt-get update && sudo apt-get install build-essential
    ```

* Build and Install 
    ```
    git clone https://github.com/kinglear007/zksync-crypto-c
    cd zksync-crypto-c & make

    sudo cp target/release/libzks_crypto.so /lib
    ```

* Add environment variable
    ```
    sudo vim ~/.bashrc
  
    export ZK_LINK_LIBRARY_PATH=/lib/libzks_crypto.so
    ```




