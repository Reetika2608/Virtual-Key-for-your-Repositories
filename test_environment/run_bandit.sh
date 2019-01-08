rm -f bandit_baseline_result.txt
bandit-baseline -f txt -r .
exit_code=$?
cat bandit_baseline_result.txt
exit $exit_code
