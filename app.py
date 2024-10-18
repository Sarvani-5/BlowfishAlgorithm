from flask import Flask, request, jsonify, render_template
from blowfish import Blowfish

app = Flask(__name__)

last_blowfish_instance = None

def validate_key(key):
    """Validate key length."""
    return 4 <= len(key) <= 56

@app.route('/')
def home():
    return render_template('blowfish.html')

@app.route('/expand_key', methods=['POST'])
def expand_key():
    data = request.get_json()
    key = data.get('key', '').encode('utf-8')

    if not validate_key(key):
        return jsonify({'error': 'Key must be between 4 and 56 bytes.'}), 400

    blowfish = Blowfish(key)
    expanded_key_hex = [hex(k) for k in blowfish.p_array]
    
    return jsonify({'expanded_key': expanded_key_hex})

@app.route('/encrypt', methods=['POST'])
def encrypt():
    global last_blowfish_instance
    
    data = request.get_json()
    key = data.get('key', '').encode('utf-8')
    plaintext = data.get('plaintext', '').encode('utf-8')

    if not validate_key(key):
        return jsonify({'error': 'Key must be between 4 and 56 bytes.'}), 400
    if not plaintext:
        return jsonify({'error': 'Plaintext cannot be empty.'}), 400

    blowfish = Blowfish(key)
    last_blowfish_instance = blowfish  
    ciphertext = blowfish.encrypt(plaintext)  
    
    return jsonify({
        'ciphertext': ciphertext.hex(), 
        'round_ciphertexts': blowfish.get_round_ciphertexts(), 
        'round_plaintexts': blowfish.get_round_plaintexts()
    })

@app.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.get_json()
    key = data.get('key', '').encode('utf-8')
    ciphertext_hex = data.get('ciphertext', '')

    if not validate_key(key):
        return jsonify({'error': 'Key must be between 4 and 56 bytes.'}), 400
    if not ciphertext_hex:
        return jsonify({'error': 'Ciphertext cannot be empty.'}), 400

    try:
        ciphertext = bytes.fromhex(ciphertext_hex)  
        blowfish = Blowfish(key)  
        last_blowfish_instance = blowfish  
        
        plaintext = blowfish.decrypt(ciphertext)  
        
        return jsonify({
            'plaintext': plaintext.decode('utf-8'), 
            'round_ciphertexts': blowfish.get_round_ciphertexts(), 
            'round_plaintexts': blowfish.get_round_plaintexts()
        })
    
    except ValueError as ve:
        return jsonify({'error': str(ve)}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/get_sboxes', methods=['GET'])
def get_sboxes():
    s_boxes_hex = [[hex(value) for value in sbox] for sbox in Blowfish.S_BOXES]
    
    return jsonify(s_boxes_hex)

@app.route('/get_round_ciphertexts', methods=['GET'])
def get_round_ciphertexts():
    
    if last_blowfish_instance is None:
        return jsonify({'error': 'No encryption performed yet.'}), 400
    
    round_ciphertexts = last_blowfish_instance.get_round_ciphertexts()  
    return jsonify(round_ciphertexts)

@app.route('/get_round_plaintexts', methods=['GET'])
def get_round_plaintexts():
    
    if last_blowfish_instance is None:
        return jsonify({'error': 'No encryption performed yet.'}), 400
    
    round_plaintexts = last_blowfish_instance.get_round_plaintexts()  
    return jsonify(round_plaintexts)

if __name__ == '__main__':
    app.run(debug=True)