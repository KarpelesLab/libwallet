//! Block reward and cumulative-supply calculations across networks. Port of
//! `reward.go`.

use num_bigint::BigInt;
use num_traits::Zero;

#[derive(Clone, Copy)]
enum RewardModel {
    Halving,
    Doge,
    Dash,
    Zero,
}

struct ChainRewardInfo {
    model: RewardModel,
    initial_reward: i64,
    halving_interval: u64,
}

fn chain_config(network: &str) -> Option<ChainRewardInfo> {
    let cfg = |model, initial_reward, halving_interval| {
        Some(ChainRewardInfo {
            model,
            initial_reward,
            halving_interval,
        })
    };
    const COIN: i64 = 100_000_000;
    match network {
        "bitcoin" | "namecoin" | "bitcoin-cash" | "bitcoin-testnet" => {
            cfg(RewardModel::Halving, 50 * COIN, 210_000)
        }
        "litecoin" => cfg(RewardModel::Halving, 50 * COIN, 840_000),
        "monacoin" => cfg(RewardModel::Halving, 50 * COIN, 1_051_200),
        "dogecoin" => cfg(RewardModel::Doge, 0, 0),
        "dash" => cfg(RewardModel::Dash, 5 * COIN, 0),
        "electraproto" => cfg(RewardModel::Zero, 0, 0),
        _ => None,
    }
}

/// Returns the block reward at `block_height` for `network`.
pub fn block_reward(network: &str, block_height: u64) -> Result<BigInt, String> {
    let info = chain_config(network).ok_or_else(|| format!("unsupported network: {network}"))?;
    Ok(match info.model {
        RewardModel::Halving => {
            halving_block_reward(info.initial_reward, info.halving_interval, block_height)
        }
        RewardModel::Doge => doge_block_reward(block_height),
        RewardModel::Dash => dash_block_reward(info.initial_reward, block_height),
        RewardModel::Zero => BigInt::zero(),
    })
}

fn halving_block_reward(base_reward: i64, halving_interval: u64, block_height: u64) -> BigInt {
    let halving_count = block_height / halving_interval;
    if halving_count > 32 {
        return BigInt::zero();
    }
    BigInt::from(base_reward) >> (halving_count as usize)
}

fn doge_block_reward(block_height: u64) -> BigInt {
    if block_height >= 600_000 {
        return BigInt::from(10_000i64 * 100_000_000);
    }
    let halving_index = block_height / 100_000; // 0..5
    let doge = 1_000_000i64 >> halving_index;
    BigInt::from(doge * 100_000_000)
}

fn dash_block_reward(base_reward: i64, block_height: u64) -> BigInt {
    let blocks_per_year = 210_240u64;
    let years = block_height / blocks_per_year;
    let numerator = BigInt::from(13).pow(years as u32);
    let denominator = BigInt::from(14).pow(years as u32);
    (BigInt::from(base_reward) * numerator) / denominator
}

/// Returns the total minted coins from block 0 through `block_height`
/// (inclusive) for `network`.
pub fn cumulative_reward(network: &str, block_height: u64) -> Result<BigInt, String> {
    let info = chain_config(network).ok_or_else(|| format!("unsupported network: {network}"))?;
    Ok(match info.model {
        RewardModel::Halving => {
            cumulative_halving(info.initial_reward, info.halving_interval, block_height)
        }
        RewardModel::Doge => cumulative_doge(block_height),
        RewardModel::Dash => cumulative_dash(info.initial_reward, block_height),
        RewardModel::Zero => BigInt::zero(),
    })
}

fn cumulative_halving(base_reward: i64, halving_interval: u64, block_height: u64) -> BigInt {
    let mut blocks_needed = block_height + 1;
    let mut total = BigInt::zero();
    let mut reward = BigInt::from(base_reward);
    let mut i = 0;
    while i < 33 && blocks_needed > 0 && reward.sign() == num_bigint::Sign::Plus {
        let interval_size = halving_interval.min(blocks_needed);
        total += BigInt::from(interval_size) * &reward;
        blocks_needed -= interval_size;
        reward >>= 1;
        i += 1;
    }
    total
}

fn cumulative_doge(block_height: u64) -> BigInt {
    let mut total = BigInt::zero();
    let mut blocks_accounted = 0u64;
    let interval_size = 100_000u64;

    for i in 0..6u64 {
        let interval_start = interval_size * i;
        let interval_end = interval_size * (i + 1);
        if block_height < interval_start {
            break;
        }
        let doge_reward = 1_000_000i64 >> i;
        let doge_reward_shibes = BigInt::from(doge_reward) * BigInt::from(100_000_000);

        let effective_end = if block_height + 1 < interval_end {
            block_height + 1
        } else {
            interval_end
        };
        let blocks_in_interval = effective_end - interval_start;
        if blocks_in_interval > 0 {
            total += BigInt::from(blocks_in_interval) * &doge_reward_shibes;
            blocks_accounted = effective_end;
            if blocks_accounted > block_height {
                return total;
            }
        }
    }

    if blocks_accounted <= block_height {
        let leftover = (block_height + 1) - blocks_accounted;
        total += BigInt::from(leftover) * BigInt::from(10_000i64 * 100_000_000);
    }
    total
}

fn cumulative_dash(base_reward: i64, block_height: u64) -> BigInt {
    let mut total = BigInt::zero();
    let blocks_per_year = 210_240u64;
    let years = block_height / blocks_per_year;
    let remainder = (block_height % blocks_per_year) + 1;

    for i in 0..years {
        let yearly = dash_yearly(base_reward, i);
        total += yearly * BigInt::from(blocks_per_year);
    }
    if remainder > 0 {
        let partial = dash_yearly(base_reward, years);
        total += partial * BigInt::from(remainder);
    }
    total
}

fn dash_yearly(base_reward: i64, year_index: u64) -> BigInt {
    if year_index == 0 {
        return BigInt::from(base_reward);
    }
    let numerator = BigInt::from(13).pow(year_index as u32);
    let denominator = BigInt::from(14).pow(year_index as u32);
    (BigInt::from(base_reward) * numerator) / denominator
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bi(v: i64) -> BigInt {
        BigInt::from(v)
    }

    #[test]
    fn block_rewards() {
        assert_eq!(block_reward("bitcoin", 0).unwrap(), bi(50 * 100_000_000));
        assert_eq!(
            block_reward("bitcoin", 209_999).unwrap(),
            bi(50 * 100_000_000)
        );
        assert_eq!(
            block_reward("bitcoin", 210_000).unwrap(),
            bi(25 * 100_000_000)
        );
        assert_eq!(block_reward("litecoin", 0).unwrap(), bi(50 * 100_000_000));
        assert_eq!(
            block_reward("dogecoin", 0).unwrap(),
            bi(1_000_000 * 100_000_000)
        );
        assert_eq!(
            block_reward("dogecoin", 600_000).unwrap(),
            bi(10_000 * 100_000_000)
        );
        assert_eq!(block_reward("dash", 0).unwrap(), bi(5 * 100_000_000));
        assert_eq!(block_reward("dash", 210_240).unwrap(), bi(464_285_714));
        assert_eq!(block_reward("electraproto", 100).unwrap(), bi(0));
        assert_eq!(block_reward("bitcoin", 100 * 210_000).unwrap(), bi(0));
        assert!(block_reward("unsupported", 0).is_err());
    }

    #[test]
    fn cumulative_rewards() {
        assert_eq!(
            cumulative_reward("bitcoin", 0).unwrap(),
            bi(50 * 100_000_000)
        );
        assert_eq!(
            cumulative_reward("bitcoin", 1).unwrap(),
            bi(100 * 100_000_000)
        );
        assert_eq!(
            cumulative_reward("bitcoin", 209_999).unwrap(),
            bi(10_500_000) * bi(100_000_000)
        );
        assert_eq!(
            cumulative_reward("bitcoin", 210_000).unwrap(),
            bi(10_500_025) * bi(100_000_000)
        );
        assert_eq!(
            cumulative_reward("dogecoin", 0).unwrap(),
            bi(1_000_000 * 100_000_000)
        );
        assert_eq!(
            cumulative_reward("dogecoin", 1).unwrap(),
            bi(2_000_000 * 100_000_000)
        );
        assert_eq!(
            cumulative_reward("dogecoin", 100_000).unwrap(),
            bi(100_000_500_000) * bi(100_000_000)
        );
        assert_eq!(
            cumulative_reward("dogecoin", 600_000).unwrap(),
            bi(196_875_010_000) * bi(100_000_000)
        );
        assert_eq!(cumulative_reward("electraproto", 999).unwrap(), bi(0));
        assert_eq!(cumulative_reward("dash", 0).unwrap(), bi(5 * 100_000_000));
        assert_eq!(cumulative_reward("dash", 1).unwrap(), bi(10 * 100_000_000));
        assert!(cumulative_reward("dash", 210_240).unwrap().sign() == num_bigint::Sign::Plus);
        assert!(cumulative_reward("unsupported", 0).is_err());
    }
}
