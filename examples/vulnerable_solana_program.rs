use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
    system_instruction,
    program::invoke,
};

entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    
    // Vulnerability: No account validation
    let user_account = next_account_info(accounts_iter)?;
    let target_account = next_account_info(accounts_iter)?;
    let system_program = next_account_info(accounts_iter)?;
    
    // Vulnerability: Missing signer check
    let amount = u64::from_le_bytes(instruction_data[0..8].try_into().unwrap());
    
    // Vulnerability: Unsafe arithmetic - could overflow
    let fee = amount * 5 / 100;
    let transfer_amount = amount + fee;
    
    // Vulnerability: No owner check before modifying account data
    let mut user_data = user_account.try_borrow_mut_data()?;
    
    // Vulnerability: Type confusion - no discriminator check
    let balance = u64::from_le_bytes(user_data[0..8].try_into().unwrap());
    
    // Vulnerability: Unchecked arithmetic
    let new_balance = balance - transfer_amount;
    
    // Vulnerability: No rent exemption check
    user_data[0..8].copy_from_slice(&new_balance.to_le_bytes());
    
    // Vulnerability: Arbitrary CPI without program ID validation
    invoke(
        &system_instruction::transfer(
            user_account.key,
            target_account.key,
            transfer_amount,
        ),
        &[user_account.clone(), target_account.clone(), system_program.clone()],
    )?;
    
    // Vulnerability: Excessive logging (performance issue)
    msg!("Transfer initiated");
    msg!("From: {}", user_account.key);
    msg!("To: {}", target_account.key);
    msg!("Amount: {}", amount);
    msg!("Fee: {}", fee);
    msg!("Total: {}", transfer_amount);
    msg!("New balance: {}", new_balance);
    msg!("Transaction complete");
    msg!("Thank you for using our service");
    msg!("Have a great day!");
    msg!("Visit us again soon!");
    
    // Vulnerability: No duplicate account check
    // Vulnerability: Using deprecated sysvar
    let _recent_blockhashes = accounts_iter.next();
    
    Ok(())
} 