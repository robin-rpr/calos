from flask import current_app as app, Blueprint, render_template, request, jsonify

# Create Blueprints
container_blueprint = Blueprint('container', __name__)
container_api_blueprint = Blueprint('container_api', __name__)

@container_api_blueprint.route('/', methods=['GET'])
def api_container():
    """List all containers"""
    try:
        response = app.executor.list_containers()
        return jsonify(response)
    except Exception as e:
        app.logger.error(f"Failed to list containers: {e}")
        return jsonify({"error": str(e)}), 500

@container_api_blueprint.route('/<string:container_id>', methods=['GET'])
def api_container_get(container_id):
    """Get container info"""
    try:
        response = app.executor.get_container_logs(container_id)
        return jsonify(response)
    except Exception as e:
        app.logger.error(f"Failed to get container info: {e}")
        return jsonify({"error": str(e)}), 500
    
@container_api_blueprint.route('/<string:container_id>', methods=['POST'])
def api_container_post(container_id):
    """Start a container"""
    try:
        # Form X-WWW-Form-Urlencoded
        image = request.form.get('image')
        command = request.form.get('command', [])
        environment = request.form.get('environment', {})

        response = app.executor.start_container(container_id, image, command, environment)
        return jsonify(response)
    except Exception as e:
        app.logger.error(f"Failed to start container: {e}")
        return jsonify({"error": str(e)}), 500
    
@container_api_blueprint.route('/<string:container_id>', methods=['DELETE'])
def api_container_delete(container_id):
    """Stop a container"""
    try:
        response = app.executor.stop_container(container_id)
        return jsonify(response)
    except Exception as e:
        app.logger.error(f"Failed to stop container: {e}")
        return jsonify({"error": str(e)}), 500

@container_blueprint.route("/<string:container_id>")
@app.cache.cached(timeout=86400) # 24 hours
def container(container_id):
    """Index"""
    return render_template('pages/container.html', container_id=container_id)

# Register blueprints
def init_app(app):
    app.register_blueprint(container_blueprint)
    app.register_blueprint(container_api_blueprint)