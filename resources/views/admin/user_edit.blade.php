@extends('adminlte::page')

@section('title', 'Edit User')

@section('content_header')
    <h1>Edit User</h1>
@stop

@section('content')
    <div class="row">
        <div class="col-12">
            @if ($errors->any())
                <x-adminlte-alert title="Ops Terjadi Masalah !" theme="danger" dismissable>
                    <ul>
                        @foreach ($errors->all() as $error)
                            <li>{{ $error }}</li>
                        @endforeach
                    </ul>
                </x-adminlte-alert>
            @endif
            <x-adminlte-card title="Identisas {{ $user->name }}" theme="secondary">
                <form action="{{ route('admin.user.store') }}" id="myform" method="post">
                    @csrf
                    <input name="id" value="{{ $user->id }}" hidden />
                    <x-adminlte-input name="name" value="{{ $user->name }}" label="Nama" placeholder="Nama Lengkap"
                        enable-old-support />
                    <x-adminlte-select2 id="role" name="role[]" label="Role / Jabatan" placeholder="Select a State"
                        enable-old-support multiple>
                        @foreach ($roles as $role)
                            <option value="{{ $role }}"
                                {{ $user->roles->pluck('name', 'id')->contains($role) ? 'selected' : '' }}>
                                {{ $role }}
                            </option>
                        @endforeach
                    </x-adminlte-select2>
                    <x-adminlte-input name="phone" value="{{ $user->phone }}" type="number" label="Nomor HP / Telepon"
                        placeholder="Nomor HP / Telepon yang dapat dihubungi" enable-old-support />
                    <x-adminlte-input name="email" value="{{ $user->email }}" type="email" label="Email"
                        placeholder="Email" enable-old-support />
                    <x-adminlte-input name="username" value="{{ $user->username }}" label="Username"
                        placeholder="Username" enable-old-support />
                    <x-adminlte-input name="password" type="password" label="Password" placeholder="Password" />
                </form>
                <x-adminlte-button form="myform" type="submit" theme="success" label="Simpan" />
                <x-adminlte-button theme="danger" label="Kembali" onclick="window.location='{{ url()->previous() }}'" />
            </x-adminlte-card>
        </div>
    </div>
    <x-adminlte-modal id="modalCustom" title="Tambah User" theme="success" v-centered static-backdrop scrollable>

    </x-adminlte-modal>
@stop

@section('plugins.Select2', true)
