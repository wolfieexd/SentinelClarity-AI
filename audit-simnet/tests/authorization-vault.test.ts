import { describe, expect, it } from "vitest";
import { Cl } from "@stacks/transactions";

const accounts = simnet.getAccounts();
const deployer = accounts.get("deployer")!;
const attacker = accounts.get("wallet_1")!;

function withdraw(amount: number, sender: string) {
  return simnet.callPublicFn(
    "authorization-vault",
    "withdraw",
    [Cl.uint(amount)],
    sender,
  ).result;
}

function treasuryBalance() {
  return simnet.callReadOnlyFn(
    "authorization-vault",
    "treasury-balance",
    [],
    deployer,
  ).result;
}

function mutatedWithdraw(amount: number, sender: string) {
  return simnet.callPublicFn(
    "unsafe-authorization-vault",
    "withdraw",
    [Cl.uint(amount)],
    sender,
  ).result;
}

describe("authorization-vault audit invariants", () => {
  it("rejects an adversarial value matrix without changing treasury state", () => {
    for (const amount of [1, 2, 10, 100, 999, 1_000, 10_000]) {
      expect(withdraw(amount, attacker)).toBeErr(Cl.uint(401));
      expect(treasuryBalance()).toBeUint(1_000);
    }
  });

  it("preserves the accounting invariant across approved withdrawals", () => {
    expect(withdraw(400, deployer)).toBeOk(Cl.uint(600));
    expect(withdraw(600, deployer)).toBeOk(Cl.uint(0));
    expect(treasuryBalance()).toBeUint(0);
    expect(withdraw(1, deployer)).toBeErr(Cl.uint(402));
    expect(treasuryBalance()).toBeUint(0);
  });

  it("demonstrates that removing authorization is exploitable", () => {
    expect(mutatedWithdraw(10, attacker)).toBeOk(Cl.uint(990));
  });
});
