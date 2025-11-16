import subprocess

msg1 = "d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f8955ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5bd8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0e99f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396f9652b6ff72a70"
msg2 = "d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f8955ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5bd8823e3156348f5bae6dacd436c919c6dd53e23487da03fd02396306d248cda0e99f33420f577ee8ce54b67080280d1ec69821bcb6a8839396f965ab6ff72a70"
bytes1 = bytes.fromhex(msg1)
bytes2 = bytes.fromhex(msg2)

count = 0
for a, b in zip(bytes1, bytes2):
    if a != b: count += 1
print(f'There are {count} bytes different between two messages\n')

run_hash1 = ["./sol1", "md5", "-h", msg1]
run_hash2 = ["./sol1", "md5", "-h", msg2]
res1 = subprocess.run(run_hash1, capture_output=True, text=True).stdout.strip()
res2 = subprocess.run(run_hash2, capture_output=True, text=True).stdout.strip()
print("------------------Comparing Hashes------------------")
assert res1 == res2, "These hashes are not the same"
print(f'They are the same!!! Here is the value {res1}')


run_hash1 = ["./sol1", "sha1", "-f", "./shattered-1.pdf"]
run_hash2 = ["./sol1", "sha1", "-f", "./shattered-2.pdf"]
res1 = subprocess.run(run_hash1, capture_output=True, text=True).stdout.strip()
res2 = subprocess.run(run_hash2, capture_output=True, text=True).stdout.strip()
print("------------------Comparing Hashes------------------")
assert res1 == res2, "These hashes are not the same"
print(f'They are the same!!! Here is the value {res1}')