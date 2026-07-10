import json
import io
from app import create_app

app = create_app('development')
client = app.test_client()

def test_upload_and_analyze():
    print("Testing /upload endpoint...")
    with open('test.pcap', 'rb') as f:
        data = {
            'file': (f, 'test.pcap')
        }
        response = client.post('/upload', data=data, content_type='multipart/form-data')
    
    print(f"Upload Status Code: {response.status_code}")
    res_json = response.get_json()
    print(f"Upload Response: {json.dumps(res_json, indent=2)}")
    
    if response.status_code != 200:
        print("Upload failed.")
        return
        
    filename = res_json['filename']
    print(f"\nTesting /analyze endpoint with filename: {filename}...")
    
    analyze_response = client.get(f'/analyze/{filename}')
    print(f"Analyze Status Code: {analyze_response.status_code}")
    
    analyze_json = analyze_response.get_json()
    print(f"Analyze Response: {json.dumps(analyze_json, indent=2)}")
    
if __name__ == '__main__':
    test_upload_and_analyze()
