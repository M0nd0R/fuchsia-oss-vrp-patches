# fix/fastrpc-vmo-oob

Finding package: `fuchsia-fastrpc-vmo-oob`

## Apply

```bash
cd fuchsia  # checkout near cc9d1f42c490350fe3803782523d2ee2ecd50187
git am patch/0001-fastrpc-Reject-mapped-VmoArgument-ranges-past-VMO-si.patch
# Official merge: Gerrit
git push origin HEAD:refs/for/main
```

This PR is the public patch artifact for Google OSS VRP (Fuchsia merges via Gerrit).
