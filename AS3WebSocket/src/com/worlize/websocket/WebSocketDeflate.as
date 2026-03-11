/************************************************************************
 *  permessage-deflate (RFC 7692) helper for AS3 WebSocket.
 *
 *  Uses the built-in flash.utils.ByteArray compress/uncompress with
 *  CompressionAlgorithm.DEFLATE which produces/consumes raw DEFLATE
 *  streams — exactly what the permessage-deflate extension requires.
 *
 *  Designed for no-context-takeover mode (each message is an
 *  independent DEFLATE block) since Flash's API does not expose
 *  persistent zlib contexts.
 ***********************************************************************/

package com.worlize.websocket
{
	import flash.utils.ByteArray;
	import flash.utils.CompressionAlgorithm;

	public class WebSocketDeflate
	{
		/**
		 * The four-byte sync flush marker that terminates every
		 * permessage-deflate compressed message (0x00 0x00 0xFF 0xFF).
		 * Per RFC 7692 §7.2.1 the sender MUST remove this trailer;
		 * per §7.2.2 the receiver MUST re-append it before inflating.
		 */
		private static const TAIL_0:int = 0x00;
		private static const TAIL_1:int = 0x00;
		private static const TAIL_2:int = 0xFF;
		private static const TAIL_3:int = 0xFF;

		/**
		 * Compress a payload for sending.
		 *
		 * 1. DEFLATE-compress the raw bytes.
		 * 2. Strip the trailing 0x00 0x00 0xFF 0xFF marker per RFC 7692 §7.2.1.
		 *
		 * @param data  The uncompressed payload (position is reset internally).
		 * @return      The compressed payload ready to be framed with RSV1=1.
		 */
		public static function compress(data:ByteArray):ByteArray {
			var buf:ByteArray = new ByteArray();
			buf.writeBytes(data, 0, data.length);
			buf.compress(CompressionAlgorithm.DEFLATE);
			buf.position = 0;
			return buf;
		}

		/**
		 * Decompress a received compressed payload.
		 *
		 * 1. Re-append the 0x00 0x00 0xFF 0xFF sync marker per RFC 7692 §7.2.2.
		 * 2. DEFLATE-uncompress.
		 *
		 * @param data  The compressed payload from a frame with RSV1=1.
		 * @return      The uncompressed payload.
		 */
		public static function decompress(data:ByteArray):ByteArray {
			var buf:ByteArray = new ByteArray();
			buf.writeBytes(data, 0, data.length);
			
			// 1. Reconstruct the Z_SYNC_FLUSH block per RFC 7692 §7.2.2
			buf.writeByte(TAIL_0);
			buf.writeByte(TAIL_1);
			buf.writeByte(TAIL_2);
			buf.writeByte(TAIL_3);
			
			// 2. Append an empty BFINAL=1 block to satisfy AS3's uncompress EOF requirement
			// 0x01: BFINAL=1, BTYPE=00, padded to byte boundary. Followed by LEN(0) and NLEN(0xFFFF)
			buf.writeByte(0x01);
			buf.writeByte(0x00);
			buf.writeByte(0x00);
			buf.writeByte(0xFF);
			buf.writeByte(0xFF);

			buf.uncompress(CompressionAlgorithm.DEFLATE);
			buf.position = 0;
			return buf;
		}

		/**
		 * Parse the server's Sec-WebSocket-Extensions value for
		 * permessage-deflate parameters.
		 *
		 * Example input:
		 *   "permessage-deflate; server_no_context_takeover; client_no_context_takeover"
		 *
		 * @return An Object with boolean/int params, or null if the
		 *         extension token is not "permessage-deflate".
		 */
		public static function parseExtensionParams(extensionString:String):Object {
			var parts:Array = extensionString.split(";");
			var token:String = trim(parts[0]);
			if (token.toLowerCase() !== "permessage-deflate") {
				return null;
			}

			var params:Object = {
				serverNoContextTakeover: false,
				clientNoContextTakeover: false,
				serverMaxWindowBits: 15,
				clientMaxWindowBits: 15
			};

			for (var i:int = 1; i < parts.length; i++) {
				var param:String = trim(parts[i]);
				var eqIdx:int = param.indexOf("=");
				var key:String;
				var value:String;
				if (eqIdx > 0) {
					key = trim(param.substring(0, eqIdx)).toLowerCase();
					value = trim(param.substring(eqIdx + 1));
				} else {
					key = param.toLowerCase();
					value = null;
				}

				if (key === "server_no_context_takeover") {
					params.serverNoContextTakeover = true;
				} else if (key === "client_no_context_takeover") {
					params.clientNoContextTakeover = true;
				} else if (key === "server_max_window_bits" && value) {
					params.serverMaxWindowBits = parseInt(value, 10);
				} else if (key === "client_max_window_bits" && value) {
					params.clientMaxWindowBits = parseInt(value, 10);
				}
			}

			return params;
		}

		/** Simple whitespace trim (avoids dependency on StringUtil). */
		private static function trim(s:String):String {
			var start:int = 0;
			var end:int = s.length - 1;
			while (start <= end && s.charCodeAt(start) <= 0x20) start++;
			while (end >= start && s.charCodeAt(end) <= 0x20) end--;
			return s.substring(start, end + 1);
		}
	}
}
