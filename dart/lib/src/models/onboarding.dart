/// Onboarding state returned by Info:onboarding.
class OnboardingState {
  final bool hasWallet;
  final bool hasAccount;
  final Map<String, dynamic> raw;

  const OnboardingState({
    required this.hasWallet,
    required this.hasAccount,
    required this.raw,
  });

  factory OnboardingState.fromJson(Map<String, dynamic> json) {
    return OnboardingState(
      hasWallet: json['has_wallet'] as bool? ?? json['HasWallet'] as bool? ?? false,
      hasAccount: json['has_account'] as bool? ?? json['HasAccount'] as bool? ?? false,
      raw: json,
    );
  }
}
