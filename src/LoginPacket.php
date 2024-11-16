<?php

/*
 * This file is part of BedrockProtocol.
 * Copyright (C) 2014-2022 PocketMine Team <https://github.com/pmmp/BedrockProtocol>
 *
 * BedrockProtocol is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

declare(strict_types=1);

namespace pocketmine\network\mcpe\protocol;

use pocketmine\network\mcpe\protocol\serializer\PacketSerializer;
use pocketmine\network\mcpe\protocol\types\login\JwtChain;
use pocketmine\utils\BinaryStream;
use function json_decode;
use function json_encode;
use function is_array;
use function is_string;
use const JSON_THROW_ON_ERROR;

class LoginPacket extends DataPacket implements ServerboundPacket {
    public const NETWORK_ID = ProtocolInfo::LOGIN_PACKET;

    public int $protocol;
    public JwtChain $chainDataJwt;
    public string $clientDataJwt;

    /**
     * Create a new LoginPacket instance.
     */
    public static function create(int $protocol, JwtChain $chainDataJwt, string $clientDataJwt): self {
        $instance = new self;
        $instance->protocol = $protocol;
        $instance->chainDataJwt = $chainDataJwt;
        $instance->clientDataJwt = $clientDataJwt;
        return $instance;
    }

    public function canBeSentBeforeLogin(): bool {
        return true;
    }

    protected function decodePayload(PacketSerializer $in): void {
        $this->protocol = $in->getInt();
        $this->decodeConnectionRequest($in->getString());
    }

    private function decodeConnectionRequest(string $binary): void {
        $connRequestReader = new BinaryStream($binary);

        $this->chainDataJwt = $this->decodeJwtChain($connRequestReader);

        $clientDataJwtLength = $connRequestReader->getLInt();
        if ($clientDataJwtLength <= 0) {
            throw new PacketDecodeException("Client data JWT length must be positive.");
        }
        $this->clientDataJwt = $connRequestReader->get($clientDataJwtLength);
    }

    private function decodeJwtChain(BinaryStream $stream): JwtChain {
        $chainDataLength = $stream->getLInt();
        if ($chainDataLength <= 0) {
            throw new PacketDecodeException("Chain data JSON length must be positive.");
        }

        try {
            $chainDataJson = json_decode($stream->get($chainDataLength), true, flags: JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new PacketDecodeException("Failed to decode chain data JSON: " . $e->getMessage());
        }

        if (!is_array($chainDataJson) || !isset($chainDataJson["chain"]) || !is_array($chainDataJson["chain"])) {
            throw new PacketDecodeException("Invalid chain data structure.");
        }

        $jwts = [];
        foreach ($chainDataJson["chain"] as $jwt) {
            if (!is_string($jwt)) {
                throw new PacketDecodeException("Chain must contain only strings.");
            }
            $jwts[] = $jwt;
        }

        $jwtChain = new JwtChain();
        $jwtChain->chain = $jwts;
        return $jwtChain;
    }

    protected function encodePayload(PacketSerializer $out): void {
        $out->putInt($this->protocol);
        $out->putString($this->encodeConnectionRequest());
    }

    private function encodeConnectionRequest(): string {
        $connRequestWriter = new BinaryStream();

        $chainDataJson = json_encode($this->chainDataJwt, JSON_THROW_ON_ERROR);
        $connRequestWriter->putLInt(strlen($chainDataJson));
        $connRequestWriter->put($chainDataJson);

        $connRequestWriter->putLInt(strlen($this->clientDataJwt));
        $connRequestWriter->put($this->clientDataJwt);

        return $connRequestWriter->getBuffer();
    }

    public function handle(PacketHandlerInterface $handler): bool {
        return $handler->handleLogin($this);
    }
}
