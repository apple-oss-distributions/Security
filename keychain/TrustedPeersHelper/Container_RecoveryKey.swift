import CoreData
import Foundation

private let logger = Logger(subsystem: "com.apple.security.trustedpeers", category: "recoverykey")

extension Container {
    func preflightVouchWithRecoveryKey(recoveryKey: String,
                                       salt: String,
                                       reply: @escaping (String?, TPSyncingPolicy?, Error?) -> Void) {
        self.semaphore.wait()
        let reply: (String?, TPSyncingPolicy?, Error?) -> Void = {
            logger.info("preflightRecoveryKey complete: \(traceError($2), privacy: .public)")
            self.semaphore.signal()
            reply($0, $1, $2)
        }

        self.fetchAndPersistChanges { fetchError in
            guard fetchError == nil else {
                logger.info("preflightRecoveryKey unable to fetch current peers: \(String(describing: fetchError), privacy: .public)")
                reply(nil, nil, fetchError)
                return
            }

            // Ensure we have all policy versions claimed by peers, including our sponsor
            self.fetchPolicyDocumentsWithSemaphore(versions: self.model.allPolicyVersions()) { _, fetchPolicyDocumentsError in
                guard fetchPolicyDocumentsError == nil else {
                    logger.info("preflightRecoveryKey unable to fetch policy documents: \(String(describing: fetchPolicyDocumentsError), privacy: .public)")
                    reply(nil, nil, fetchPolicyDocumentsError)
                    return
                }

                self.moc.performAndWait {
                    guard let egoPeerID = self.containerMO.egoPeerID,
                        let egoPermData = self.containerMO.egoPeerPermanentInfo,
                        let egoPermSig = self.containerMO.egoPeerPermanentInfoSig,
                        let egoStableData = self.containerMO.egoPeerStableInfo,
                        let egoStableSig = self.containerMO.egoPeerStableInfoSig else {
                            logger.info("preflightRecoveryKey: no ego peer ID")
                            reply(nil, nil, ContainerError.noPreparedIdentity)
                            return
                    }

                    let keyFactory = TPECPublicKeyFactory()
                    guard let selfPermanentInfo = TPPeerPermanentInfo(peerID: egoPeerID, data: egoPermData, sig: egoPermSig, keyFactory: keyFactory) else {
                        reply(nil, nil, ContainerError.invalidPermanentInfoOrSig)
                        return
                    }

                    guard let selfStableInfo = TPPeerStableInfo(data: egoStableData, sig: egoStableSig) else {
                        logger.info("cannot create TPPeerStableInfo")
                        reply(nil, nil, ContainerError.invalidStableInfoOrSig)
                        return
                    }

                    var recoveryKeys: RecoveryKey
                    do {
                        recoveryKeys = try RecoveryKey(recoveryKeyString: recoveryKey, recoverySalt: salt)
                    } catch {
                        logger.error("preflightRecoveryKey: failed to create recovery keys: \(String(describing: error), privacy: .public)")
                        reply(nil, nil, ContainerError.failedToCreateRecoveryKey)
                        return
                    }

                    // Dear model: if i were to use this recovery key, what peers would I end up using?
                    guard self.model.isRecoveryKeyEnrolled() else {
                        logger.info("preflightRecoveryKey: recovery Key is not enrolled")
                        reply(nil, nil, ContainerError.recoveryKeysNotEnrolled)
                        return
                    }

                    guard let sponsorPeerID = self.model.peerIDThatTrustsRecoveryKeys(TPRecoveryKeyPair(signingKeyData: recoveryKeys.peerKeys.signingKey.publicKey.keyData,
                                                                                                        encryptionKeyData: recoveryKeys.peerKeys.encryptionKey.publicKey.keyData),
                                                                                      canIntroducePeer: selfPermanentInfo,
                                                                                      stableInfo: selfStableInfo) else {
                        logger.info("preflightRecoveryKey Untrusted recovery key set")
                        reply(nil, nil, ContainerError.untrustedRecoveryKeys)
                        return
                    }

                    guard let sponsor = self.model.peer(withID: sponsorPeerID) else {
                        logger.info("preflightRecoveryKey Failed to find peer with ID")
                        reply(nil, nil, ContainerError.sponsorNotRegistered(sponsorPeerID))
                        return
                    }

                    do {
                        let bestPolicy = try self.model.policy(forPeerIDs: sponsor.dynamicInfo?.includedPeerIDs ?? [sponsor.peerID],
                                                               candidatePeerID: egoPeerID,
                                                               candidateStableInfo: sponsor.stableInfo)
                        let syncingPolicy = try bestPolicy.syncingPolicy(forModel: selfPermanentInfo.modelID,
                                                                         syncUserControllableViews: sponsor.stableInfo?.syncUserControllableViews ?? .UNKNOWN, isInheritedAccount: selfStableInfo.isInheritedAccount)

                        reply(recoveryKeys.peerKeys.peerID, syncingPolicy, nil)
                    } catch {
                        logger.error("preflightRecoveryKey: error fetching policy: \(String(describing: error), privacy: .public)")
                        reply(nil, nil, error)
                        return
                    }
                }
            }
        }
    }

    func preflightVouchWithCustodianRecoveryKey(crk: TrustedPeersHelperCustodianRecoveryKey,
                                                reply: @escaping (String?, TPSyncingPolicy?, Error?) -> Void) {
        self.semaphore.wait()
        let reply: (String?, TPSyncingPolicy?, Error?) -> Void = {
            logger.info("preflightCustodianRecoveryKey complete: \(traceError($2), privacy: .public)")
            self.semaphore.signal()
            reply($0, $1, $2)
        }

        self.fetchAndPersistChangesIfNeeded { fetchError in
            guard fetchError == nil else {
                logger.info("preflightCustodianRecoveryKey unable to fetch current peers: \(String(describing: fetchError), privacy: .public)")
                reply(nil, nil, fetchError)
                return
            }

            // Ensure we have all policy versions claimed by peers, including our sponsor
            self.fetchPolicyDocumentsWithSemaphore(versions: self.model.allPolicyVersions()) { _, fetchPolicyDocumentsError in
                guard fetchPolicyDocumentsError == nil else {
                    logger.info("preflightCustodianRecoveryKey unable to fetch policy documents: \(String(describing: fetchPolicyDocumentsError), privacy: .public)")
                    reply(nil, nil, fetchPolicyDocumentsError)
                    return
                }

                self.moc.performAndWait {
                    guard let egoPeerID = self.containerMO.egoPeerID,
                        let egoPermData = self.containerMO.egoPeerPermanentInfo,
                        let egoPermSig = self.containerMO.egoPeerPermanentInfoSig,
                        let egoStableData = self.containerMO.egoPeerStableInfo,
                        let egoStableSig = self.containerMO.egoPeerStableInfoSig else {
                            logger.info("preflightCustodianRecoveryKey: no ego peer ID")
                            reply(nil, nil, ContainerError.noPreparedIdentity)
                            return
                    }

                    let keyFactory = TPECPublicKeyFactory()
                    guard let selfPermanentInfo = TPPeerPermanentInfo(peerID: egoPeerID, data: egoPermData, sig: egoPermSig, keyFactory: keyFactory) else {
                        reply(nil, nil, ContainerError.invalidPermanentInfoOrSig)
                        return
                    }

                    guard let selfStableInfo = TPPeerStableInfo(data: egoStableData, sig: egoStableSig) else {
                        reply(nil, nil, ContainerError.invalidStableInfoOrSig)
                        return
                    }

                    guard let uuid = UUID(uuidString: crk.uuid) else {
                        logger.info("Unable to parse uuid \(crk.uuid, privacy: .public)")
                        reply(nil, nil, ContainerError.recoveryKeysNotEnrolled)
                        return
                    }

                    guard let tpcrk = self.model.findCustodianRecoveryKey(with: uuid) else {
                        logger.info("Unable to find custodian recovery key \(crk.uuid, privacy: .public) on model")
                        reply(nil, nil, ContainerError.recoveryKeysNotEnrolled)
                        return
                    }

                    let crkRecoveryKey: CustodianRecoveryKey
                    do {
                        crkRecoveryKey = try CustodianRecoveryKey(tpCustodian: tpcrk, recoveryKeyString: crk.recoveryString, recoverySalt: crk.salt)
                    } catch {
                        logger.error("preflightCustodianRecoveryKey: failed to create custodian recovery keys: \(String(describing: error), privacy: .public)")
                        reply(nil, nil, ContainerError.failedToCreateRecoveryKey)
                        return
                    }

                    // Dear model: if I were to use this custodian recovery key, what peers would I end up using?
                    guard self.model.isCustodianRecoveryKeyTrusted(tpcrk.peerID) else {
                        logger.info("preflightCustodianRecoveryKey: custodian recovery Key is not enrolled")
                        reply(nil, nil, ContainerError.recoveryKeysNotEnrolled)
                        return
                    }

                    guard let sponsorPeerID = self.model.peerIDThatTrustsCustodianRecoveryKeys(tpcrk,
                                                                                               canIntroducePeer: selfPermanentInfo,
                                                                                               stableInfo: selfStableInfo) else {
                        logger.info("preflightCustodianRecoveryKey Untrusted custodian recovery key")
                        reply(nil, nil, ContainerError.untrustedRecoveryKeys)
                        return
                    }

                    guard let sponsor = self.model.peer(withID: sponsorPeerID) else {
                        logger.info("preflightCustodianRecoveryKey Failed to find peer with ID")
                        reply(nil, nil, ContainerError.sponsorNotRegistered(sponsorPeerID))
                        return
                    }

                    do {
                        let bestPolicy = try self.model.policy(forPeerIDs: sponsor.dynamicInfo?.includedPeerIDs ?? [sponsor.peerID],
                                                               candidatePeerID: egoPeerID,
                                                               candidateStableInfo: sponsor.stableInfo)
                        let syncingPolicy = try bestPolicy.syncingPolicy(forModel: selfPermanentInfo.modelID,
                                                                         syncUserControllableViews: sponsor.stableInfo?.syncUserControllableViews ?? .UNKNOWN, isInheritedAccount: selfStableInfo.isInheritedAccount)

                        reply(crkRecoveryKey.peerKeys.peerID, syncingPolicy, nil)
                    } catch {
                        logger.error("preflightCustodianRecoveryKey: error fetching policy: \(String(describing: error), privacy: .public)")
                        reply(nil, nil, error)
                        return
                    }
                }
            }
        }
    }

    func preflightRecoverOctagonWithRecoveryKey(recoveryKey: String,
                                                salt: String,
                                                reply: @escaping (Bool, Error?) -> Void) {
        self.semaphore.wait()
        let reply: (Bool, Error?) -> Void = {
            logger.info("preflightRecoverOctagonWithRecoveryKey complete: \(traceError($1), privacy: .public)")
            self.semaphore.signal()
            reply($0, $1)
        }

        self.fetchAndPersistChanges { error in
            guard error == nil else {
                logger.error("preflightRecoverOctagonWithRecoveryKey unable to fetch changes: \(String(describing: error), privacy: .public)")
                reply(false, error)
                return
            }

            self.moc.performAndWait {

                // inflate this RK
                var recoveryKeys: RecoveryKey
                do {
                    recoveryKeys = try RecoveryKey(recoveryKeyString: recoveryKey, recoverySalt: salt)
                } catch {
                    logger.error("preflightRecoverOctagonWithRecoveryKey: failed to create recovery keys: \(String(describing: error), privacy: .public)")
                    reply(false, ContainerError.failedToCreateRecoveryKey)
                    return
                }

                // is a RK enrolled and trusted?
                guard self.model.isRecoveryKeyEnrolled() else {
                    logger.info("preflightRecoverOctagonWithRecoveryKey: recovery Key is not enrolled")
                    reply(false, ContainerError.recoveryKeysNotEnrolled)
                    return
                }

                // does this passed in recovery key match the enrolled one?
                guard self.model.recoverySigningPublicKey() == recoveryKeys.peerKeys.publicSigningKey?.keyData && self.model.recoveryEncryptionPublicKey() == recoveryKeys.peerKeys.publicEncryptionKey?.keyData else {
                    logger.info("preflightRecoverOctagonWithRecoveryKey: recovery Key is incorrect")
                    reply(false, ContainerError.recoveryKeyIsNotCorrect)
                    return
                }

                reply(true, nil)
            }
        }
    }
}
