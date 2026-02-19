import base64
from PIL import Image
import io

# Create a simple 1x1 pixel PNG image
img = Image.new('RGB', (1, 1), color='red')
buffer = io.BytesIO()
img.save(buffer, format='PNG')
img_str = base64.b64encode(buffer.getvalue()).decode()

print(f"data:image/png;base64,{img_str}")